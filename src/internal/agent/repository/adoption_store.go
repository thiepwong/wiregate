package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type StoredSecretInput struct {
	Context  secret.Context
	Envelope secret.Envelope
}

// AdoptionImportPlan is the redacted metadata that will be imported when an
// observed wg-quick interface becomes owned. It contains no key material.
type AdoptionImportPlan struct {
	PoolCIDRs       []string
	PeerCount       int
	AllocationCount int
}

type adoptionPool struct {
	Family  int
	CIDR    string
	Gateway string
}

type adoptionAllocation struct {
	AllowedIPID string
	PeerID      string
	PoolCIDR    string
	Address     string
	OldPurpose  string
	NewPurpose  string
}

type adoptionImport struct {
	Pools       []adoptionPool
	Assignments []adoptionAllocation
	PeerCount   int
}

func (r *Repository) PreviewAdoptionImport(
	ctx context.Context,
	interfaceID string,
) (AdoptionImportPlan, error) {
	tx, err := r.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AdoptionImportPlan{}, err
	}
	defer tx.Rollback()
	plan, err := buildAdoptionImport(ctx, tx, interfaceID)
	if err != nil {
		return AdoptionImportPlan{}, err
	}
	result := AdoptionImportPlan{
		PeerCount: plan.PeerCount, AllocationCount: len(plan.Assignments),
		PoolCIDRs: make([]string, 0, len(plan.Pools)),
	}
	for _, pool := range plan.Pools {
		result.PoolCIDRs = append(result.PoolCIDRs, pool.CIDR)
	}
	return result, tx.Commit()
}

func (r *Repository) SnapshotOperation(
	ctx context.Context,
	operationID string,
	secretContext secret.Context,
	envelope secret.Envelope,
	fileHash, runtimeFingerprint string,
	synchronizedSecrets []StoredSecretInput,
) error {
	now := r.now()
	envelopeID, err := ids.NewV7(now)
	if err != nil {
		return err
	}
	snapshotID, err := ids.NewV7(now.Add(time.Nanosecond))
	if err != nil {
		return err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var interfaceID, state string
	if err := tx.QueryRowContext(ctx, `
		SELECT interface_id, state FROM operations WHERE id = ?`, operationID,
	).Scan(&interfaceID, &state); err != nil {
		return err
	}
	if state != string(agentoperation.StateValidated) {
		return fmt.Errorf("operation must be validated before snapshot")
	}
	if err := insertEnvelope(ctx, tx, envelopeID, secretContext, envelope, now); err != nil {
		return err
	}
	for index, synchronized := range synchronizedSecrets {
		synchronizedID, err := ids.NewV7(now.Add(time.Duration(index+2) * time.Nanosecond))
		if err != nil {
			return err
		}
		if err := insertEnvelope(
			ctx, tx, synchronizedID, synchronized.Context, synchronized.Envelope, now,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO operation_staged_secrets(
				operation_id, secret_envelope_id, peer_id
			) VALUES (?, ?, ?)`,
			operationID, synchronizedID, synchronized.Context.OwnerID,
		); err != nil {
			return fmt.Errorf("stage adopted peer secret: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO snapshots(
			id, interface_id, operation_id, secret_envelope_id,
			file_hash, runtime_fingerprint, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		snapshotID, interfaceID, operationID, envelopeID,
		nullable(fileHash), nullable(runtimeFingerprint), now.UnixMilli(),
	); err != nil {
		return fmt.Errorf("insert operation snapshot: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET state = 'snapshotted', snapshot_id = ?, updated_at_ms = ?
		WHERE id = ? AND state = 'validated'`,
		snapshotID, now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("operation state conflict while storing snapshot")
	}
	return tx.Commit()
}

// ApplyAdoption performs only agent-owned metadata changes. It never rewrites
// the WireGuard file or touches runtime state. Existing peer profiles, address
// pools and allocations are imported atomically so the adopted interface is
// immediately usable for both old-peer lifecycle and new-peer enrollment.
func (r *Repository) ApplyAdoption(ctx context.Context, operationID string) (int64, error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var interfaceID, operationType, state, actorID, actorRole, requestID string
	var reason sql.NullString
	var expectedRevision sql.NullInt64
	var expectedHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT interface_id, type, state, actor_id, actor_role, request_id,
		       reason, expected_revision, COALESCE(original_file_hash, '')
		FROM operations WHERE id = ?`, operationID,
	).Scan(
		&interfaceID, &operationType, &state, &actorID, &actorRole, &requestID,
		&reason, &expectedRevision, &expectedHash,
	); err != nil {
		return 0, err
	}
	if operationType != "adopt_interface" || state != string(agentoperation.StateExecuting) ||
		!expectedRevision.Valid {
		return 0, errors.New("invalid adoption operation state")
	}
	var currentMode, backend, currentHash, runtimeFingerprint string
	var currentRevision int64
	var saveConfig bool
	if err := tx.QueryRowContext(ctx, `
		SELECT management_mode, backend, COALESCE(file_hash, ''),
		       COALESCE(runtime_fingerprint, ''), revision, save_config_detected
		FROM interfaces WHERE id = ?`, interfaceID,
	).Scan(
		&currentMode, &backend, &currentHash, &runtimeFingerprint,
		&currentRevision, &saveConfig,
	); err != nil {
		return 0, err
	}
	if currentMode != "observed" || backend != "wg_quick" || saveConfig ||
		currentRevision != expectedRevision.Int64 || currentHash != expectedHash {
		return 0, errors.New("adoption revision or eligibility conflict")
	}
	nextRevision := currentRevision + 1
	revisionID, err := ids.NewV7(now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO config_revisions(
			id, interface_id, sequence, file_hash, runtime_fingerprint,
			operation_id, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		revisionID, interfaceID, nextRevision, nullable(currentHash),
		nullable(runtimeFingerprint), operationID, now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("insert adoption revision: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE interfaces
		SET management_mode = 'adopted', revision = ?,
		    last_applied_revision_id = ?, drift_state = 'none', updated_at_ms = ?
		WHERE id = ? AND management_mode = 'observed' AND revision = ? AND file_hash = ?`,
		nextRevision, revisionID, now.UnixMilli(), interfaceID,
		currentRevision, currentHash,
	)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errors.New("adoption interface update conflict")
	}
	if err := importAdoptionMetadata(ctx, tx, operationID, interfaceID, now); err != nil {
		return 0, err
	}
	if err := attachStagedAdoptionSecrets(ctx, tx, operationID, now); err != nil {
		return 0, err
	}
	auditID, err := ids.NewV7(now.Add(time.Nanosecond))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, actor_type, actor_id, actor_role, action, target_type,
			target_id, request_id, operation_id, before_revision,
			after_revision, result, reason, created_at_ms
		) VALUES (?, 'user', ?, ?, 'adopt_interface', 'interface', ?, ?, ?, ?, ?, 'success', ?, ?)`,
		auditID, actorID, actorRole, interfaceID, requestID, operationID,
		currentRevision, nextRevision, reason, now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("insert adoption audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET state = 'verifying', updated_at_ms = ?
		WHERE id = ? AND state = 'executing'`,
		now.UnixMilli(), operationID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextRevision, nil
}

func buildAdoptionImport(
	ctx context.Context,
	tx *sql.Tx,
	interfaceID string,
) (adoptionImport, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT family, address, prefix_length
		FROM interface_addresses
		WHERE interface_id = ?
		ORDER BY family, prefix_length DESC, address`, interfaceID,
	)
	if err != nil {
		return adoptionImport{}, err
	}
	poolByCIDR := make(map[string]adoptionPool)
	for rows.Next() {
		var family, bits int
		var addressText string
		if err := rows.Scan(&family, &addressText, &bits); err != nil {
			_ = rows.Close()
			return adoptionImport{}, err
		}
		address, err := netip.ParseAddr(addressText)
		if err != nil || address.BitLen() == 0 || bits < 0 || bits > address.BitLen() {
			_ = rows.Close()
			return adoptionImport{}, errors.New("adoption interface address is invalid")
		}
		prefix := netip.PrefixFrom(address, bits).Masked()
		cidr := prefix.String()
		if existing, ok := poolByCIDR[cidr]; ok && existing.Gateway != address.String() {
			_ = rows.Close()
			return adoptionImport{}, fmt.Errorf("ambiguous gateways for adoption pool %s", cidr)
		}
		poolByCIDR[cidr] = adoptionPool{Family: family, CIDR: cidr, Gateway: address.String()}
	}
	if err := rows.Close(); err != nil {
		return adoptionImport{}, err
	}
	if len(poolByCIDR) == 0 {
		return adoptionImport{}, errors.New("adoption requires at least one interface address for IPAM")
	}
	plan := adoptionImport{Pools: make([]adoptionPool, 0, len(poolByCIDR))}
	for _, pool := range poolByCIDR {
		plan.Pools = append(plan.Pools, pool)
	}
	sort.Slice(plan.Pools, func(i, j int) bool {
		if plan.Pools[i].Family != plan.Pools[j].Family {
			return plan.Pools[i].Family < plan.Pools[j].Family
		}
		return plan.Pools[i].CIDR < plan.Pools[j].CIDR
	})

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM peers WHERE interface_id = ?`, interfaceID,
	).Scan(&plan.PeerCount); err != nil {
		return adoptionImport{}, err
	}
	allowedRows, err := tx.QueryContext(ctx, `
		SELECT pai.id, pai.peer_id, pai.cidr, pai.purpose
		FROM peer_allowed_ips pai
		JOIN peers p ON p.id = pai.peer_id
		WHERE p.interface_id = ? AND p.lifecycle_state = 'active'
		ORDER BY pai.cidr, pai.peer_id`, interfaceID,
	)
	if err != nil {
		return adoptionImport{}, err
	}
	used := make(map[string]string)
	for allowedRows.Next() {
		var id, peerID, cidr, purpose string
		if err := allowedRows.Scan(&id, &peerID, &cidr, &purpose); err != nil {
			_ = allowedRows.Close()
			return adoptionImport{}, err
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			_ = allowedRows.Close()
			return adoptionImport{}, fmt.Errorf("invalid adopted AllowedIPs %q", cidr)
		}
		newPurpose := "routed_subnet"
		poolCIDR := ""
		isHost := (prefix.Addr().Is4() && prefix.Bits() == 32) ||
			(prefix.Addr().Is6() && prefix.Bits() == 128)
		if isHost {
			for _, pool := range plan.Pools {
				poolPrefix, _ := netip.ParsePrefix(pool.CIDR)
				if poolPrefix.Contains(prefix.Addr()) {
					if poolCIDR != "" {
						_ = allowedRows.Close()
						return adoptionImport{}, fmt.Errorf("peer address %s matches multiple adoption pools", prefix.Addr())
					}
					poolCIDR = pool.CIDR
				}
			}
			if poolCIDR != "" {
				newPurpose = "tunnel_address"
				key := poolCIDR + "|" + prefix.Addr().String()
				if owner := used[key]; owner != "" && owner != peerID {
					_ = allowedRows.Close()
					return adoptionImport{}, fmt.Errorf("peer address %s is assigned to multiple peers", prefix.Addr())
				}
				used[key] = peerID
				plan.Assignments = append(plan.Assignments, adoptionAllocation{
					AllowedIPID: id, PeerID: peerID, PoolCIDR: poolCIDR,
					Address: prefix.Addr().String(), OldPurpose: purpose, NewPurpose: newPurpose,
				})
			}
		}
		if poolCIDR == "" && purpose != newPurpose {
			plan.Assignments = append(plan.Assignments, adoptionAllocation{
				AllowedIPID: id, PeerID: peerID, OldPurpose: purpose, NewPurpose: newPurpose,
			})
		}
	}
	if err := allowedRows.Close(); err != nil {
		return adoptionImport{}, err
	}
	return plan, nil
}

func importAdoptionMetadata(
	ctx context.Context,
	tx *sql.Tx,
	operationID, interfaceID string,
	now time.Time,
) error {
	plan, err := buildAdoptionImport(ctx, tx, interfaceID)
	if err != nil {
		return fmt.Errorf("prepare adoption IPAM import: %w", err)
	}
	peerRows, err := tx.QueryContext(ctx, `
		SELECT p.id
		FROM peers p
		LEFT JOIN client_profiles cp ON cp.peer_id = p.id
		WHERE p.interface_id = ? AND cp.id IS NULL
		ORDER BY p.id`, interfaceID,
	)
	if err != nil {
		return err
	}
	var missingProfiles []string
	for peerRows.Next() {
		var peerID string
		if err := peerRows.Scan(&peerID); err != nil {
			_ = peerRows.Close()
			return err
		}
		missingProfiles = append(missingProfiles, peerID)
	}
	if err := peerRows.Close(); err != nil {
		return err
	}
	for index, peerID := range missingProfiles {
		profileID, err := ids.NewV7(now.Add(time.Duration(index+100) * time.Nanosecond))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO client_profiles(
				id, peer_id, profile_state, dns_json, created_at_ms, updated_at_ms
			) VALUES (?, ?, 'external', '[]', ?, ?)`,
			profileID, peerID, now.UnixMilli(), now.UnixMilli(),
		); err != nil {
			return fmt.Errorf("create adopted external profile: %w", err)
		}
		if err := recordAdoptionImport(ctx, tx, operationID, "client_profile", profileID, ""); err != nil {
			return err
		}
	}

	poolIDs := make(map[string]string, len(plan.Pools))
	for index, pool := range plan.Pools {
		poolID, err := ids.NewV7(now.Add(time.Duration(index+1000) * time.Nanosecond))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO address_pools(
				id, interface_id, family, cidr, gateway_address, created_at_ms
			) VALUES (?, ?, ?, ?, ?, ?)`,
			poolID, interfaceID, pool.Family, pool.CIDR, pool.Gateway, now.UnixMilli(),
		); err != nil {
			return fmt.Errorf("import adoption address pool: %w", err)
		}
		poolIDs[pool.CIDR] = poolID
		if err := recordAdoptionImport(ctx, tx, operationID, "address_pool", poolID, ""); err != nil {
			return err
		}
	}
	for index, item := range plan.Assignments {
		if item.OldPurpose != item.NewPurpose {
			if _, err := tx.ExecContext(ctx, `
				UPDATE peer_allowed_ips SET purpose = ? WHERE id = ?`,
				item.NewPurpose, item.AllowedIPID,
			); err != nil {
				return err
			}
			if err := recordAdoptionImport(
				ctx, tx, operationID, "allowed_ip_purpose", item.AllowedIPID, item.OldPurpose,
			); err != nil {
				return err
			}
		}
		if item.PoolCIDR == "" {
			continue
		}
		allocationID, err := ids.NewV7(now.Add(time.Duration(index+2000) * time.Nanosecond))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO address_allocations(
				id, pool_id, peer_id, address, state, created_at_ms, updated_at_ms
			) VALUES (?, ?, ?, ?, 'allocated', ?, ?)`,
			allocationID, poolIDs[item.PoolCIDR], item.PeerID, item.Address,
			now.UnixMilli(), now.UnixMilli(),
		); err != nil {
			return fmt.Errorf("import adopted peer allocation: %w", err)
		}
		if err := recordAdoptionImport(ctx, tx, operationID, "address_allocation", allocationID, ""); err != nil {
			return err
		}
	}
	return nil
}

func recordAdoptionImport(
	ctx context.Context,
	tx *sql.Tx,
	operationID, kind, resourceID, previous string,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO adoption_import_ledger(
			operation_id, resource_kind, resource_id, previous_value
		) VALUES (?, ?, ?, ?)`, operationID, kind, resourceID, nullable(previous),
	)
	return err
}

// FinalizeAdoption atomically makes the staged secret ownership permanent and
// commits the operation. Until this point RollbackAdoption can identify every
// envelope and profile touched by the adoption.
func (r *Repository) FinalizeAdoption(ctx context.Context, operationID string) error {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET state = 'committed', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND type = 'adopt_interface' AND state = 'verifying'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return fmt.Errorf("finalize adoption operation: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("adoption operation state conflict while finalizing")
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM operation_staged_secrets WHERE operation_id = ?`, operationID,
	); err != nil {
		return fmt.Errorf("finalize staged adoption secrets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM adoption_import_ledger WHERE operation_id = ?`, operationID,
	); err != nil {
		return fmt.Errorf("finalize adoption import ledger: %w", err)
	}
	return tx.Commit()
}

// RollbackAdoption reverses only objects proven to be owned by this operation.
// It is safe to call after a crash in snapshotted, executing, verifying or
// rolling_back state and never rewrites the observed WireGuard config.
func (r *Repository) RollbackAdoption(ctx context.Context, operationID string) error {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var interfaceID, state, requestID string
	var expectedRevision sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT interface_id, state, request_id, expected_revision
		FROM operations
		WHERE id = ? AND type = 'adopt_interface'`, operationID,
	).Scan(&interfaceID, &state, &requestID, &expectedRevision); err != nil {
		return err
	}
	if state != string(agentoperation.StateRollingBack) || !expectedRevision.Valid {
		return errors.New("adoption operation must be rolling back")
	}
	staged, err := listStagedAdoptionSecrets(ctx, tx, operationID)
	if err != nil {
		return err
	}
	for _, item := range staged {
		if item.CreatedProfile {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM client_profiles
				WHERE id = ? AND peer_id = ? AND preshared_secret_id = ?`,
				item.ProfileID, item.PeerID, item.EnvelopeID,
			); err != nil {
				return fmt.Errorf("remove staged client profile: %w", err)
			}
		} else if item.ProfileID != "" {
			if _, err := tx.ExecContext(ctx, `
				UPDATE client_profiles
				SET preshared_secret_id = ?, updated_at_ms = ?
				WHERE id = ? AND peer_id = ? AND preshared_secret_id = ?`,
				nullable(item.PreviousEnvelopeID), now.UnixMilli(),
				item.ProfileID, item.PeerID, item.EnvelopeID,
			); err != nil {
				return fmt.Errorf("restore prior client profile secret: %w", err)
			}
		}
	}
	if err := rollbackAdoptionImports(ctx, tx, operationID); err != nil {
		return err
	}

	var mode string
	var revision int64
	var lastRevisionID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT management_mode, revision, last_applied_revision_id
		FROM interfaces WHERE id = ?`, interfaceID,
	).Scan(&mode, &revision, &lastRevisionID); err != nil {
		return err
	}
	if !((mode == "observed" && revision == expectedRevision.Int64) ||
		(mode == "adopted" && revision == expectedRevision.Int64+1)) {
		return errors.New("adoption interface state is ambiguous during rollback")
	}
	if mode == "adopted" && revision == expectedRevision.Int64+1 {
		var owned int
		if lastRevisionID.Valid {
			if err := tx.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM config_revisions
				WHERE id = ? AND operation_id = ?`,
				lastRevisionID.String, operationID,
			).Scan(&owned); err != nil {
				return err
			}
		}
		if owned != 1 {
			return errors.New("refusing to rollback an adoption revision not owned by the operation")
		}
		var previousRevisionID sql.NullString
		_ = tx.QueryRowContext(ctx, `
			SELECT id FROM config_revisions
			WHERE interface_id = ? AND sequence = ? AND operation_id != ?
			LIMIT 1`,
			interfaceID, expectedRevision.Int64, operationID,
		).Scan(&previousRevisionID)
		update, err := tx.ExecContext(ctx, `
			UPDATE interfaces
			SET management_mode = 'observed', revision = ?,
			    last_applied_revision_id = ?, drift_state = 'unknown',
			    updated_at_ms = ?
			WHERE id = ? AND management_mode = 'adopted'
			  AND revision = ? AND last_applied_revision_id = ?`,
			expectedRevision.Int64, nullableNullString(previousRevisionID),
			now.UnixMilli(), interfaceID, revision, lastRevisionID.String,
		)
		if err != nil {
			return fmt.Errorf("rollback adopted interface metadata: %w", err)
		}
		if affected, _ := update.RowsAffected(); affected != 1 {
			return errors.New("adopted interface changed during rollback")
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM config_revisions WHERE id = ? AND operation_id = ?`,
			lastRevisionID.String, operationID,
		); err != nil {
			return fmt.Errorf("remove rolled-back adoption revision: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM operation_staged_secrets WHERE operation_id = ?`, operationID,
	); err != nil {
		return err
	}
	for _, item := range staged {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM secret_envelopes WHERE id = ?`, item.EnvelopeID,
		); err != nil {
			return fmt.Errorf("remove rolled-back staged envelope: %w", err)
		}
	}
	auditID, err := ids.NewV7(now.Add(time.Nanosecond))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, actor_type, actor_id, action, target_type, target_id,
			request_id, operation_id, before_revision, after_revision,
			result, details_redacted, created_at_ms
		) VALUES (?, 'system', 'agent-recovery', 'rollback_adoption',
		          'interface', ?, ?, ?, ?, ?, 'success',
		          'adoption metadata and staged secrets rolled back', ?)`,
		auditID, interfaceID, requestID, operationID,
		revision, expectedRevision.Int64, now.UnixMilli(),
	); err != nil {
		return fmt.Errorf("audit adoption rollback: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations
		SET state = 'rolled_back', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'rolling_back'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("adoption operation state conflict while rolling back")
	}
	return tx.Commit()
}

func rollbackAdoptionImports(ctx context.Context, tx *sql.Tx, operationID string) error {
	type item struct {
		kind, id, previous string
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT resource_kind, resource_id, COALESCE(previous_value, '')
		FROM adoption_import_ledger
		WHERE operation_id = ?
		ORDER BY resource_kind, resource_id`, operationID,
	)
	if err != nil {
		return err
	}
	var items []item
	for rows.Next() {
		var value item
		if err := rows.Scan(&value.kind, &value.id, &value.previous); err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, value := range items {
		if value.kind == "allowed_ip_purpose" {
			if _, err := tx.ExecContext(ctx, `
				UPDATE peer_allowed_ips SET purpose = ? WHERE id = ?`,
				value.previous, value.id,
			); err != nil {
				return fmt.Errorf("restore adopted AllowedIPs purpose: %w", err)
			}
		}
	}
	for _, kind := range []string{"address_allocation", "client_profile", "address_pool"} {
		table := map[string]string{
			"address_allocation": "address_allocations",
			"client_profile":     "client_profiles",
			"address_pool":       "address_pools",
		}[kind]
		for _, value := range items {
			if value.kind != kind {
				continue
			}
			query := "DELETE FROM " + table + " WHERE id = ?"
			if _, err := tx.ExecContext(ctx, query, value.id); err != nil {
				return fmt.Errorf("remove adopted %s: %w", kind, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM adoption_import_ledger WHERE operation_id = ?`, operationID,
	); err != nil {
		return err
	}
	return nil
}

type stagedAdoptionSecret struct {
	EnvelopeID         string
	PeerID             string
	ProfileID          string
	PreviousEnvelopeID string
	CreatedProfile     bool
}

func attachStagedAdoptionSecrets(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
	now time.Time,
) error {
	staged, err := listStagedAdoptionSecrets(ctx, tx, operationID)
	if err != nil {
		return err
	}
	for index, item := range staged {
		var profileID string
		var previous sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT id, preshared_secret_id
			FROM client_profiles WHERE peer_id = ?`, item.PeerID,
		).Scan(&profileID, &previous)
		created := false
		if errors.Is(err, sql.ErrNoRows) {
			profileID, err = ids.NewV7(now.Add(time.Duration(index+100) * time.Nanosecond))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO client_profiles(
					id, peer_id, profile_state, preshared_secret_id,
					dns_json, created_at_ms, updated_at_ms
				) VALUES (?, ?, 'external', ?, '[]', ?, ?)`,
				profileID, item.PeerID, item.EnvelopeID,
				now.UnixMilli(), now.UnixMilli(),
			); err != nil {
				return fmt.Errorf("create adopted external client profile: %w", err)
			}
			created = true
		} else if err != nil {
			return err
		} else if _, err := tx.ExecContext(ctx, `
			UPDATE client_profiles
			SET preshared_secret_id = ?, updated_at_ms = ?
			WHERE id = ?`,
			item.EnvelopeID, now.UnixMilli(), profileID,
		); err != nil {
			return fmt.Errorf("synchronize adopted peer secret: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE operation_staged_secrets
			SET profile_id = ?, previous_secret_envelope_id = ?,
			    created_profile = ?
			WHERE operation_id = ? AND secret_envelope_id = ?`,
			profileID, nullableNullString(previous), created,
			operationID, item.EnvelopeID,
		); err != nil {
			return fmt.Errorf("record staged secret ownership: %w", err)
		}
	}
	return nil
}

func listStagedAdoptionSecrets(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
) ([]stagedAdoptionSecret, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT secret_envelope_id, peer_id, COALESCE(profile_id, ''),
		       COALESCE(previous_secret_envelope_id, ''), created_profile
		FROM operation_staged_secrets
		WHERE operation_id = ?
		ORDER BY peer_id`, operationID,
	)
	if err != nil {
		return nil, fmt.Errorf("list staged adoption secrets: %w", err)
	}
	defer rows.Close()
	var result []stagedAdoptionSecret
	for rows.Next() {
		var item stagedAdoptionSecret
		if err := rows.Scan(
			&item.EnvelopeID, &item.PeerID, &item.ProfileID,
			&item.PreviousEnvelopeID, &item.CreatedProfile,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func nullableNullString(value sql.NullString) any {
	if !value.Valid || value.String == "" {
		return nil
	}
	return value.String
}

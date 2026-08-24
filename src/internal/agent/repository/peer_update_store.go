// File: src/internal/agent/repository/peer_update_store.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type PeerUpdateInput struct {
	PeerID              string
	InterfaceID         string
	Name                string
	Endpoint            string
	PersistentKeepalive int
	AllowedIPs          []string
	ClientRoutes        []string
	OriginalFileHash    string
	ProposedFileHash    string
	RuntimeFingerprint  string
}

type updatePool struct {
	ID   string
	CIDR netip.Prefix
}

type updateAllocation struct {
	PoolID  string
	Address string
}

func (r *Repository) CompletePeerUpdate(
	ctx context.Context,
	operationID string,
	input PeerUpdateInput,
) (int64, error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state string
	var expected sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT state, expected_revision
		FROM operations
		WHERE id = ? AND type = 'update_peer' AND interface_id = ?`,
		operationID, input.InterfaceID,
	).Scan(&state, &expected); err != nil {
		return 0, err
	}
	if state != string(agentoperation.StateExecuting) || !expected.Valid {
		return 0, errors.New("peer update operation is not executing")
	}
	var revision int64
	var fileHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT revision, COALESCE(file_hash, '')
		FROM interfaces WHERE id = ?`, input.InterfaceID,
	).Scan(&revision, &fileHash); err != nil {
		return 0, err
	}
	if revision != expected.Int64 || fileHash != input.OriginalFileHash {
		return 0, errors.New("interface changed during peer update")
	}
	var lifecycle string
	if err := tx.QueryRowContext(ctx, `
		SELECT lifecycle_state FROM peers WHERE id = ? AND interface_id = ?`,
		input.PeerID, input.InterfaceID,
	).Scan(&lifecycle); err != nil {
		return 0, err
	}
	if lifecycle != "active" {
		return 0, errors.New("only an active peer can be updated")
	}
	pools, err := loadUpdatePools(ctx, tx, input.InterfaceID)
	if err != nil {
		return 0, err
	}
	purposes, desiredAllocations, err := classifyUpdatedAllowedIPs(input.AllowedIPs, pools)
	if err != nil {
		return 0, err
	}
	if err := syncPeerAllocations(ctx, tx, input.PeerID, desiredAllocations, now); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM peer_allowed_ips WHERE peer_id = ?`, input.PeerID); err != nil {
		return 0, err
	}
	for index, value := range input.AllowedIPs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return 0, err
		}
		canonical := prefix.Masked().String()
		allowedID, err := ids.NewV7(now.Add(time.Duration(index+10) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO peer_allowed_ips(id, peer_id, cidr, purpose, created_at_ms)
			VALUES (?, ?, ?, ?, ?)`,
			allowedID, input.PeerID, canonical, purposes[canonical], now.UnixMilli(),
		); err != nil {
			return 0, err
		}
	}
	var profileID string
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM client_profiles WHERE peer_id = ?`, input.PeerID,
	).Scan(&profileID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_routes WHERE client_profile_id = ?`, profileID); err != nil {
		return 0, err
	}
	for index, route := range input.ClientRoutes {
		routeID, err := ids.NewV7(now.Add(time.Duration(index+100) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO client_routes(id, client_profile_id, cidr) VALUES (?, ?, ?)`,
			routeID, profileID, route,
		); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE peers
		SET name = ?, endpoint = ?, persistent_keepalive = ?, updated_at_ms = ?
		WHERE id = ? AND interface_id = ?`,
		input.Name, nullable(input.Endpoint), input.PersistentKeepalive,
		now.UnixMilli(), input.PeerID, input.InterfaceID,
	); err != nil {
		return 0, err
	}
	nextRevision := revision + 1
	revisionID, err := ids.NewV7(now.Add(500 * time.Nanosecond))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO config_revisions(
			id, interface_id, sequence, file_hash, runtime_fingerprint,
			operation_id, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		revisionID, input.InterfaceID, nextRevision, input.ProposedFileHash,
		nullable(input.RuntimeFingerprint), operationID, now.UnixMilli(),
	); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE interfaces
		SET file_hash = ?, runtime_fingerprint = ?, revision = ?,
			last_applied_revision_id = ?, drift_state = 'none', updated_at_ms = ?
		WHERE id = ? AND revision = ? AND COALESCE(file_hash, '') = ?`,
		input.ProposedFileHash, nullable(input.RuntimeFingerprint), nextRevision,
		revisionID, now.UnixMilli(), input.InterfaceID, revision, input.OriginalFileHash,
	)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errors.New("interface changed while updating peer")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET proposed_file_hash = ?, state = 'verifying', updated_at_ms = ?
		WHERE id = ? AND state = 'executing'`,
		input.ProposedFileHash, now.UnixMilli(), operationID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextRevision, nil
}

func loadUpdatePools(ctx context.Context, tx *sql.Tx, interfaceID string) ([]updatePool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, cidr FROM address_pools WHERE interface_id = ? ORDER BY family, cidr`,
		interfaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []updatePool
	for rows.Next() {
		var id, cidr string
		if err := rows.Scan(&id, &cidr); err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		result = append(result, updatePool{ID: id, CIDR: prefix})
	}
	return result, rows.Err()
}

func classifyUpdatedAllowedIPs(
	values []string,
	pools []updatePool,
) (map[string]string, []updateAllocation, error) {
	purposes := make(map[string]string, len(values))
	var allocations []updateAllocation
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, err
		}
		prefix = prefix.Masked()
		purpose := "routed_subnet"
		isHost := (prefix.Addr().Is4() && prefix.Bits() == 32) ||
			(prefix.Addr().Is6() && prefix.Bits() == 128)
		if isHost {
			var selected *updatePool
			for index := range pools {
				if pools[index].CIDR.Contains(prefix.Addr()) {
					if selected != nil {
						return nil, nil, fmt.Errorf("peer address %s matches multiple pools", prefix.Addr())
					}
					selected = &pools[index]
				}
			}
			if selected != nil {
				purpose = "tunnel_address"
				allocations = append(allocations, updateAllocation{
					PoolID: selected.ID, Address: prefix.Addr().String(),
				})
			}
		}
		purposes[prefix.String()] = purpose
	}
	return purposes, allocations, nil
}

func syncPeerAllocations(
	ctx context.Context,
	tx *sql.Tx,
	peerID string,
	desired []updateAllocation,
	now time.Time,
) error {
	desiredKeys := make(map[string]updateAllocation, len(desired))
	for _, item := range desired {
		desiredKeys[item.PoolID+"|"+item.Address] = item
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, pool_id, address
		FROM address_allocations
		WHERE peer_id = ? AND state = 'allocated'`, peerID,
	)
	if err != nil {
		return err
	}
	type currentAllocation struct{ id, poolID, address string }
	var current []currentAllocation
	for rows.Next() {
		var item currentAllocation
		if err := rows.Scan(&item.id, &item.poolID, &item.address); err != nil {
			_ = rows.Close()
			return err
		}
		current = append(current, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range current {
		key := item.poolID + "|" + item.address
		if _, keep := desiredKeys[key]; keep {
			delete(desiredKeys, key)
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE address_allocations
			SET state = 'quarantined', quarantine_until_ms = ?, updated_at_ms = ?
			WHERE id = ? AND state = 'allocated'`,
			now.Add(24*time.Hour).UnixMilli(), now.UnixMilli(), item.id,
		); err != nil {
			return err
		}
	}
	index := 0
	for _, item := range desiredKeys {
		var count int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM address_allocations
			WHERE pool_id = ? AND address = ? AND state IN ('allocated','quarantined')`,
			item.PoolID, item.Address,
		).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("peer address %s is unavailable", item.Address)
		}
		allocationID, err := ids.NewV7(now.Add(time.Duration(index+300) * time.Nanosecond))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO address_allocations(
				id, pool_id, peer_id, address, state, created_at_ms, updated_at_ms
			) VALUES (?, ?, ?, ?, 'allocated', ?, ?)`,
			allocationID, item.PoolID, peerID, item.Address,
			now.UnixMilli(), now.UnixMilli(),
		); err != nil {
			return err
		}
		index++
	}
	return nil
}

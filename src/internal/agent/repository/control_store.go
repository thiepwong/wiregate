// File: src/internal/agent/repository/control_store.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
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
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type ManagedInterfaceInput struct {
	ID                 string
	Name               string
	ConfigPath         string
	ListenPort         int
	PublicKey          string
	DeploymentProfile  string
	FirewallMode       string
	AutoStart          bool
	Addresses          []string
	FileHash           string
	RuntimeFingerprint string
}

type ManagedResourceInput struct {
	Kind        string
	Path        string
	Fingerprint string
}

// ReserveManagedInterface creates the database identity needed by the durable
// snapshot foreign key. It does not claim a host path or mutate networking.
func (r *Repository) ReserveManagedInterface(
	ctx context.Context,
	operationID string,
	input ManagedInterfaceInput,
) error {
	if input.ID == "" || input.Name == "" || input.ConfigPath == "" {
		return errors.New("managed interface identity is required")
	}
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var operationType, state string
	if err := tx.QueryRowContext(ctx, `
		SELECT type, state FROM operations WHERE id = ?`, operationID,
	).Scan(&operationType, &state); err != nil {
		return err
	}
	if operationType != "create_interface" || state != string(agentoperation.StateValidated) {
		return errors.New("create-interface operation is not validated")
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id FROM interfaces WHERE name = ?`, input.Name).Scan(&existing)
	if err == nil {
		return errors.New("interface name is already reserved")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO interfaces(
			id, name, backend, namespace_kind, management_mode,
			config_path, service_owner, service_unit, config_present,
			runtime_present, revision, drift_state, deployment_profile,
			firewall_mode, managed_firewall_backend, listen_port,
			public_key, auto_start, service_state,
			last_seen_at_ms, created_at_ms, updated_at_ms
		) VALUES (?, ?, 'wg_quick', 'host', 'managed', ?, 'systemd', ?,
		          0, 0, 0, 'unknown', ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)`,
		input.ID, input.Name, input.ConfigPath, "wg-quick@"+input.Name+".service",
		input.DeploymentProfile, input.FirewallMode,
		map[bool]string{true: "nftables", false: "none"}[input.FirewallMode == "managed_nft"],
		input.ListenPort, nullable(input.PublicKey), input.AutoStart,
		now.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return fmt.Errorf("reserve managed interface: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations SET interface_id = ?, updated_at_ms = ?
		WHERE id = ? AND state = 'validated' AND interface_id IS NULL`,
		input.ID, now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("create-interface operation reservation conflict")
	}
	return tx.Commit()
}

// CompleteManagedInterface records only host objects that were already
// verified by their typed adapters, then advances the operation to verifying.
func (r *Repository) CompleteManagedInterface(
	ctx context.Context,
	operationID string,
	input ManagedInterfaceInput,
	resources []ManagedResourceInput,
) (int64, error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state, interfaceID string
	if err := tx.QueryRowContext(ctx, `
		SELECT state, interface_id FROM operations
		WHERE id = ? AND type = 'create_interface'`, operationID,
	).Scan(&state, &interfaceID); err != nil {
		return 0, err
	}
	if state != string(agentoperation.StateExecuting) || interfaceID != input.ID {
		return 0, errors.New("create-interface operation is not executing")
	}
	revisionID, err := ids.NewV7(now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO config_revisions(
			id, interface_id, sequence, file_hash, runtime_fingerprint,
			operation_id, created_at_ms
		) VALUES (?, ?, 1, ?, ?, ?, ?)`,
		revisionID, input.ID, nullable(input.FileHash),
		nullable(input.RuntimeFingerprint), operationID, now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("record managed interface revision: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE interfaces
		SET config_present = 1, runtime_present = 1, file_hash = ?,
		    runtime_fingerprint = ?, revision = 1,
		    last_applied_revision_id = ?, drift_state = 'none',
		    listen_port = ?, public_key = ?, auto_start = ?,
		    service_state = 'active', last_seen_at_ms = ?, updated_at_ms = ?
		WHERE id = ? AND management_mode = 'managed' AND revision = 0`,
		input.FileHash, nullable(input.RuntimeFingerprint), revisionID,
		input.ListenPort, nullable(input.PublicKey), input.AutoStart,
		now.UnixMilli(), now.UnixMilli(), input.ID,
	)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errors.New("managed interface reservation changed")
	}
	for index, value := range input.Addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return 0, fmt.Errorf("parse managed address: %w", err)
		}
		addressID, err := ids.NewV7(now.Add(time.Duration(index+1) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO interface_addresses(
				id, interface_id, family, address, prefix_length, source
			) VALUES (?, ?, ?, ?, ?, 'managed')`,
			addressID, input.ID, family, prefix.Addr().String(), prefix.Bits(),
		); err != nil {
			return 0, err
		}
		poolID, err := ids.NewV7(now.Add(time.Duration(index+100) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO address_pools(
				id, interface_id, family, cidr, gateway_address, created_at_ms
			) VALUES (?, ?, ?, ?, ?, ?)`,
			poolID, input.ID, family, prefix.Masked().String(),
			prefix.Addr().String(), now.UnixMilli(),
		); err != nil {
			return 0, err
		}
	}
	for index, resource := range resources {
		resourceID, err := ids.NewV7(now.Add(time.Duration(index+200) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO managed_resources(
				id, interface_id, operation_id, resource_kind,
				path, fingerprint, created_at_ms
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			resourceID, input.ID, operationID, resource.Kind,
			nullable(resource.Path), nullable(resource.Fingerprint), now.UnixMilli(),
		); err != nil {
			return 0, fmt.Errorf("record managed resource: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET proposed_file_hash = ?, state = 'verifying', updated_at_ms = ?
		WHERE id = ? AND state = 'executing'`,
		input.FileHash, now.UnixMilli(), operationID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return 1, nil
}

func (r *Repository) FinalizeControlOperation(
	ctx context.Context,
	operationID, action, targetType, targetID string,
	beforeRevision, afterRevision int64,
) error {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var actorID, actorRole, requestID string
	var reason sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT actor_id, actor_role, request_id, reason
		FROM operations WHERE id = ? AND state = 'verifying'`, operationID,
	).Scan(&actorID, &actorRole, &requestID, &reason); err != nil {
		return err
	}
	auditID, err := ids.NewV7(now)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, actor_type, actor_id, actor_role, action, target_type,
			target_id, request_id, operation_id, before_revision,
			after_revision, result, reason, created_at_ms
		) VALUES (?, 'user', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'success', ?, ?)`,
		auditID, actorID, actorRole, action, targetType, targetID,
		requestID, operationID, beforeRevision, afterRevision, reason, now.UnixMilli(),
	); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations SET state = 'committed', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'verifying'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("operation verification state changed")
	}
	return tx.Commit()
}

func (r *Repository) FinishControlRollback(ctx context.Context, operationID string) error {
	now := r.now()
	result, err := r.database.ExecContext(ctx, `
		UPDATE operations SET state = 'rolled_back', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'rolling_back'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("operation rollback state changed")
	}
	return nil
}

func (r *Repository) LoadOperationSnapshot(
	ctx context.Context,
	operationID string,
) (secret.Context, secret.Envelope, error) {
	tx, err := r.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return secret.Context{}, secret.Envelope{}, err
	}
	defer tx.Rollback()
	var envelopeID string
	if err := tx.QueryRowContext(ctx, `
		SELECT secret_envelope_id FROM snapshots WHERE operation_id = ?`, operationID,
	).Scan(&envelopeID); err != nil {
		return secret.Context{}, secret.Envelope{}, err
	}
	secretContext, envelope, err := loadEnvelope(ctx, tx, envelopeID)
	if err != nil {
		return secret.Context{}, secret.Envelope{}, err
	}
	return secretContext, envelope, tx.Commit()
}

// RollbackManagedInterface removes only a still-revision-zero reservation.
// Host resources must already have been compensated and verified by the
// control service before this metadata rollback is called.
func (r *Repository) RollbackManagedInterface(ctx context.Context, operationID string) error {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var interfaceID, state string
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(interface_id, ''), state FROM operations
		WHERE id = ? AND type = 'create_interface'`, operationID,
	).Scan(&interfaceID, &state); err != nil {
		return err
	}
	if state != string(agentoperation.StateRollingBack) {
		return errors.New("create-interface operation is not rolling back")
	}
	var envelopeID sql.NullString
	_ = tx.QueryRowContext(ctx, `
		SELECT secret_envelope_id FROM snapshots WHERE operation_id = ?`, operationID,
	).Scan(&envelopeID)
	if interfaceID != "" {
		var revision int64
		var ownedRevision int
		if err := tx.QueryRowContext(ctx, `
			SELECT revision FROM interfaces WHERE id = ?`, interfaceID,
		).Scan(&revision); err != nil {
			return err
		}
		if revision == 1 {
			if err := tx.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM config_revisions
				WHERE interface_id = ? AND sequence = 1 AND operation_id = ?`,
				interfaceID, operationID,
			).Scan(&ownedRevision); err != nil {
				return err
			}
		}
		if revision > 1 || (revision == 1 && ownedRevision != 1) {
			return errors.New("managed interface has a revision not owned by this operation")
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE operations SET interface_id = NULL WHERE id = ?`, operationID,
		); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
			DELETE FROM interfaces
			WHERE id = ? AND management_mode = 'managed' AND revision IN (0,1)`, interfaceID,
		)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return errors.New("managed interface is no longer a rollback-safe reservation")
		}
	}
	if envelopeID.Valid {
		if _, err := tx.ExecContext(ctx, `DELETE FROM secret_envelopes WHERE id = ?`, envelopeID.String); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations SET state = 'rolled_back', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'rolling_back'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("create-interface rollback state changed")
	}
	return tx.Commit()
}

func (r *Repository) RejectManagedInterfaceReservation(
	ctx context.Context,
	operationID string,
	failure *agentoperation.Failure,
) error {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var interfaceID, state string
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(interface_id, ''), state FROM operations
		WHERE id = ? AND type = 'create_interface'`, operationID,
	).Scan(&interfaceID, &state); err != nil {
		return err
	}
	if state != string(agentoperation.StateValidated) {
		return errors.New("create-interface operation cannot be rejected from its current state")
	}
	if interfaceID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET interface_id = NULL WHERE id = ?`, operationID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
			DELETE FROM interfaces WHERE id = ? AND management_mode = 'managed' AND revision = 0`,
			interfaceID,
		)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return errors.New("managed interface reservation changed before rejection")
		}
	}
	var code, message any
	if failure != nil {
		code, message = failure.Code, failure.Message
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operations SET state = 'rejected', error_code = ?,
		    error_message_redacted = ?, updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'validated'`,
		code, message, now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("create-interface rejection state changed")
	}
	return tx.Commit()
}

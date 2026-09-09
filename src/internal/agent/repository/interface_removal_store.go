// File: src/internal/agent/repository/interface_removal_store.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-09-09
// Description: Persist journaled removal of WireGate-managed interfaces.

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type ManagedResourceRecord struct {
	Kind        string
	Path        string
	Fingerprint string
}

func (r *Repository) ListManagedResources(
	ctx context.Context,
	interfaceID string,
) ([]ManagedResourceRecord, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT mr.resource_kind, COALESCE(mr.path, ''), mr.fingerprint
		FROM managed_resources mr
		JOIN interfaces i ON i.id = mr.interface_id
		WHERE mr.interface_id = ? AND i.management_mode = 'managed'
		ORDER BY mr.resource_kind`, interfaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ManagedResourceRecord
	for rows.Next() {
		var record ManagedResourceRecord
		if err := rows.Scan(&record.Kind, &record.Path, &record.Fingerprint); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

// FinalizeManagedInterfaceRemoval atomically removes interface-owned metadata
// while retaining redacted operation and audit history. Host resources must
// already be absent and verified by the control service.
func (r *Repository) FinalizeManagedInterfaceRemoval(
	ctx context.Context,
	operationID string,
) (revision int64, peerCount int, err error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	var interfaceID, operationType, state, actorID, actorRole, requestID string
	var reason sql.NullString
	var expectedRevision sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT interface_id, type, state, actor_id, actor_role, request_id,
		       reason, expected_revision
		FROM operations WHERE id = ?`, operationID,
	).Scan(
		&interfaceID, &operationType, &state, &actorID, &actorRole,
		&requestID, &reason, &expectedRevision,
	); err != nil {
		return 0, 0, err
	}
	if operationType != "set_interface_state" || state != string(agentoperation.StateVerifying) ||
		!expectedRevision.Valid {
		return 0, 0, errors.New("interface-removal operation is not ready to finalize")
	}
	var managementMode string
	if err := tx.QueryRowContext(ctx, `
		SELECT management_mode, revision FROM interfaces WHERE id = ?`, interfaceID,
	).Scan(&managementMode, &revision); err != nil {
		return 0, 0, err
	}
	if managementMode != "managed" || revision != expectedRevision.Int64 {
		return 0, 0, errors.New("managed interface changed before removal finalization")
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM peers WHERE interface_id = ?`, interfaceID,
	).Scan(&peerCount); err != nil {
		return 0, 0, err
	}

	secretRows, err := tx.QueryContext(ctx, `
		SELECT id FROM secret_envelopes
		WHERE (owner_type = 'peer' AND owner_id IN (
		         SELECT id FROM peers WHERE interface_id = ?
		      ))
		   OR (owner_type = 'artifact' AND owner_id IN (
		         SELECT a.id FROM one_time_artifacts a
		         JOIN peers p ON p.id = a.peer_id
		         WHERE p.interface_id = ?
		      ))
		   OR (owner_type = 'operation' AND owner_id IN (
		         SELECT id FROM operations WHERE interface_id = ?
		      ))`, interfaceID, interfaceID, interfaceID,
	)
	if err != nil {
		return 0, 0, err
	}
	var secretIDs []string
	for secretRows.Next() {
		var id string
		if err := secretRows.Scan(&id); err != nil {
			_ = secretRows.Close()
			return 0, 0, err
		}
		secretIDs = append(secretIDs, id)
	}
	if err := secretRows.Err(); err != nil {
		_ = secretRows.Close()
		return 0, 0, err
	}
	if err := secretRows.Close(); err != nil {
		return 0, 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET interface_id = NULL WHERE interface_id = ?`, interfaceID,
	); err != nil {
		return 0, 0, err
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM interfaces
		WHERE id = ? AND management_mode = 'managed' AND revision = ?`,
		interfaceID, revision,
	)
	if err != nil {
		return 0, 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, 0, errors.New("managed interface changed during removal")
	}
	for _, id := range secretIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM secret_envelopes WHERE id = ?`, id); err != nil {
			return 0, 0, fmt.Errorf("delete interface-owned secret: %w", err)
		}
	}

	auditID, err := ids.NewV7(now)
	if err != nil {
		return 0, 0, err
	}
	details := fmt.Sprintf("removed managed interface with %d peer(s)", peerCount)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, actor_type, actor_id, actor_role, action, target_type,
			target_id, request_id, operation_id, before_revision,
			after_revision, result, reason, details_redacted, created_at_ms
		) VALUES (?, 'user', ?, ?, 'remove_interface', 'interface', ?, ?, ?, ?,
		          NULL, 'success', ?, ?, ?)`,
		auditID, actorID, actorRole, interfaceID, requestID, operationID,
		revision, reason, details, now.UnixMilli(),
	); err != nil {
		return 0, 0, err
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE operations
		SET state = 'committed', updated_at_ms = ?, finished_at_ms = ?
		WHERE id = ? AND state = 'verifying'`,
		now.UnixMilli(), now.UnixMilli(), operationID,
	)
	if err != nil {
		return 0, 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, 0, errors.New("interface-removal operation state changed")
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return revision, peerCount, nil
}

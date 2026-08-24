// File: src/internal/agent/repository/peer_lifecycle_store.go
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
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

func (r *Repository) CompletePeerLifecycle(
	ctx context.Context,
	operationID, peerID, mutation, originalHash, proposedHash, runtimeFingerprint string,
	archivedBlock *SecretInput,
) (int64, error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var interfaceID, operationType, state string
	var expected sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT o.interface_id, o.type, o.state, o.expected_revision
		FROM operations o WHERE o.id = ?`, operationID,
	).Scan(&interfaceID, &operationType, &state, &expected); err != nil {
		return 0, err
	}
	if operationType != mutation+"_peer" || state != string(agentoperation.StateExecuting) || !expected.Valid {
		return 0, errors.New("peer lifecycle operation is not executing")
	}
	var revision int64
	var fileHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT revision, COALESCE(file_hash, '') FROM interfaces WHERE id = ?`, interfaceID,
	).Scan(&revision, &fileHash); err != nil {
		return 0, err
	}
	if revision != expected.Int64 || fileHash != originalHash {
		return 0, errors.New("interface changed during peer lifecycle operation")
	}
	var previousArchivedID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT archived_block_secret_id FROM peers WHERE id = ? AND interface_id = ?`,
		peerID, interfaceID,
	).Scan(&previousArchivedID); err != nil {
		return 0, err
	}
	var nextArchivedID any
	if mutation == "enable" {
		if !previousArchivedID.Valid {
			return 0, errors.New("disabled peer has no archived block")
		}
	} else {
		if archivedBlock == nil || archivedBlock.Context.OwnerType != "peer" ||
			archivedBlock.Context.OwnerID != peerID || archivedBlock.Context.Purpose != "archived_peer_block" {
			return 0, errors.New("peer lifecycle archive is required")
		}
		if previousArchivedID.Valid {
			return 0, errors.New("active peer already has an archived block")
		}
		archiveID, err := ids.NewV7(now.Add(time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if err := insertEnvelope(
			ctx, tx, archiveID, archivedBlock.Context, archivedBlock.Envelope, now,
		); err != nil {
			return 0, fmt.Errorf("store archived peer block: %w", err)
		}
		nextArchivedID = archiveID
	}
	nextRevision := revision + 1
	revisionID, err := ids.NewV7(now.Add(2 * time.Nanosecond))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO config_revisions(
			id, interface_id, sequence, file_hash, runtime_fingerprint, operation_id, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		revisionID, interfaceID, nextRevision, proposedHash, nullable(runtimeFingerprint),
		operationID, now.UnixMilli(),
	); err != nil {
		return 0, err
	}
	targetState := "disabled"
	observedPresent := 0
	if mutation == "enable" {
		targetState = "active"
		observedPresent = 1
	} else if mutation == "revoke" {
		targetState = "revoked"
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE peers SET lifecycle_state = ?, observed_present = ?, archived_block_secret_id = ?, updated_at_ms = ?,
			revoked_at_ms = CASE WHEN ? = 'revoked' THEN ? ELSE revoked_at_ms END
		WHERE id = ? AND interface_id = ?`,
		targetState, observedPresent, nextArchivedID, now.UnixMilli(), targetState, now.UnixMilli(), peerID, interfaceID,
	)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errors.New("peer changed during lifecycle operation")
	}
	if mutation == "revoke" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE address_allocations SET state = 'quarantined', quarantine_until_ms = ?, updated_at_ms = ?
			WHERE peer_id = ? AND state = 'allocated'`,
			now.Add(24*time.Hour).UnixMilli(), now.UnixMilli(), peerID,
		); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE client_profiles SET profile_state = 'revoked', updated_at_ms = ? WHERE peer_id = ?`,
			now.UnixMilli(), peerID,
		); err != nil {
			return 0, err
		}
	}
	if mutation == "enable" {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM secret_envelopes WHERE id = ?`, previousArchivedID.String,
		); err != nil {
			return 0, fmt.Errorf("remove restored peer archive: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE interfaces SET file_hash = ?, runtime_fingerprint = ?, revision = ?,
			last_applied_revision_id = ?, drift_state = 'none', updated_at_ms = ?
		WHERE id = ? AND revision = ? AND COALESCE(file_hash, '') = ?`,
		proposedHash, nullable(runtimeFingerprint), nextRevision, revisionID,
		now.UnixMilli(), interfaceID, revision, originalHash,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET proposed_file_hash = ?, state = 'verifying', updated_at_ms = ?
		WHERE id = ? AND state = 'executing'`, proposedHash, now.UnixMilli(), operationID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextRevision, nil
}

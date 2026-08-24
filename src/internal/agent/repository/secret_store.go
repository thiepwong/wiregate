// File: src/internal/agent/repository/secret_store.go
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

	"github.com/wiregate-project/wiregate/internal/agent/artifact"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

func (r *Repository) CreateOneTime(
	ctx context.Context,
	peerID string,
	secretContext secret.Context,
	envelope secret.Envelope,
	tokenHash []byte,
	expiresAt time.Time,
) (string, error) {
	if len(tokenHash) != 32 || !expiresAt.After(r.now()) {
		return "", errors.New("invalid one-time artifact token hash or expiry")
	}
	now := r.now()
	envelopeID, err := ids.NewV7(now)
	if err != nil {
		return "", err
	}
	artifactID, err := ids.NewV7(now.Add(time.Nanosecond))
	if err != nil {
		return "", err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := insertEnvelope(ctx, tx, envelopeID, secretContext, envelope, now); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO one_time_artifacts(
			id, peer_id, secret_envelope_id, token_hash, state, expires_at_ms, created_at_ms
		) VALUES (?, ?, ?, ?, 'ready', ?, ?)`,
		artifactID, peerID, envelopeID, tokenHash, expiresAt.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return "", fmt.Errorf("insert one-time artifact: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit one-time artifact: %w", err)
	}
	return artifactID, nil
}

func (r *Repository) BeginOneTimeConsume(
	ctx context.Context,
	tokenHash []byte,
	now time.Time,
) (artifact.Record, error) {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return artifact.Record{}, err
	}
	defer tx.Rollback()
	var record artifact.Record
	var envelopeID string
	var expiresAtMS int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id, peer_id, secret_envelope_id, expires_at_ms
		FROM one_time_artifacts
		WHERE token_hash = ? AND state = 'ready' AND expires_at_ms > ?`,
		tokenHash, now.UnixMilli(),
	).Scan(&record.ID, &record.PeerID, &envelopeID, &expiresAtMS); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return artifact.Record{}, artifact.ErrUnavailable
		}
		return artifact.Record{}, fmt.Errorf("find one-time artifact: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE one_time_artifacts SET state = 'consuming'
		WHERE id = ? AND state = 'ready'`, record.ID)
	if err != nil {
		return artifact.Record{}, fmt.Errorf("claim one-time artifact: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return artifact.Record{}, artifact.ErrUnavailable
	}
	secretContext, envelope, err := loadEnvelope(ctx, tx, envelopeID)
	if err != nil {
		return artifact.Record{}, err
	}
	record.Context = secretContext
	record.Envelope = envelope
	record.ExpiresAt = time.UnixMilli(expiresAtMS).UTC()
	if err := tx.Commit(); err != nil {
		return artifact.Record{}, fmt.Errorf("commit one-time claim: %w", err)
	}
	return record, nil
}

func (r *Repository) FinalizeOneTimeConsume(ctx context.Context, artifactID string, now time.Time) error {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var envelopeID string
	if err := tx.QueryRowContext(ctx, `
		SELECT secret_envelope_id FROM one_time_artifacts
		WHERE id = ? AND state = 'consuming'`, artifactID,
	).Scan(&envelopeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE one_time_artifacts
		SET state = 'consumed', consumed_at_ms = ?, secret_envelope_id = NULL
		WHERE id = ? AND state = 'consuming'`,
		now.UnixMilli(), artifactID,
	); err != nil {
		return fmt.Errorf("finalize one-time artifact: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM secret_envelopes WHERE id = ?`, envelopeID); err != nil {
		return fmt.Errorf("delete consumed secret envelope: %w", err)
	}
	return tx.Commit()
}

// CleanupOneTime fails closed after restart: consuming artifacts become
// consumed, expired ready artifacts become expired, and both lose ciphertext.
func (r *Repository) CleanupOneTime(ctx context.Context, now time.Time) error {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT id, secret_envelope_id, state
		FROM one_time_artifacts
		WHERE state = 'consuming' OR (state = 'ready' AND expires_at_ms <= ?)`,
		now.UnixMilli(),
	)
	if err != nil {
		return err
	}
	type cleanup struct{ id, envelopeID, state string }
	var records []cleanup
	for rows.Next() {
		var item cleanup
		if err := rows.Scan(&item.id, &item.envelopeID, &item.state); err != nil {
			_ = rows.Close()
			return err
		}
		records = append(records, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range records {
		target := "expired"
		var consumedAt any
		if item.state == "consuming" {
			target = "consumed"
			consumedAt = now.UnixMilli()
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE one_time_artifacts
			SET state = ?, consumed_at_ms = ?, secret_envelope_id = NULL
			WHERE id = ?`, target, consumedAt, item.id,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM secret_envelopes WHERE id = ?`, item.envelopeID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertEnvelope(
	ctx context.Context,
	tx *sql.Tx,
	id string,
	secretContext secret.Context,
	envelope secret.Envelope,
	now time.Time,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO secret_envelopes(
			id, owner_type, owner_id, purpose, algorithm, ciphertext,
			payload_nonce, wrapped_dek, wrap_nonce, key_version, aad_version,
			secret_fingerprint, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, secretContext.OwnerType, secretContext.OwnerID, secretContext.Purpose,
		envelope.Algorithm, envelope.Ciphertext, envelope.PayloadNonce,
		envelope.WrappedDEK, envelope.WrapNonce, envelope.KeyVersion,
		envelope.AADVersion, envelope.SecretFingerprint, now.UnixMilli(), now.UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("insert secret envelope: %w", err)
	}
	return nil
}

func loadEnvelope(
	ctx context.Context,
	tx *sql.Tx,
	id string,
) (secret.Context, secret.Envelope, error) {
	var secretContext secret.Context
	secretContext.GatewayID = "" // Filled from system_state below.
	var envelope secret.Envelope
	var keyVersion, aadVersion int64
	err := tx.QueryRowContext(ctx, `
		SELECT owner_type, owner_id, purpose, algorithm, ciphertext,
		       payload_nonce, wrapped_dek, wrap_nonce, key_version, aad_version,
		       COALESCE(secret_fingerprint, X'')
		FROM secret_envelopes WHERE id = ?`, id,
	).Scan(
		&secretContext.OwnerType, &secretContext.OwnerID, &secretContext.Purpose,
		&envelope.Algorithm, &envelope.Ciphertext, &envelope.PayloadNonce,
		&envelope.WrappedDEK, &envelope.WrapNonce, &keyVersion, &aadVersion,
		&envelope.SecretFingerprint,
	)
	if err != nil {
		return secret.Context{}, secret.Envelope{}, fmt.Errorf("load secret envelope: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT gateway_id FROM system_state WHERE singleton_id = 1`,
	).Scan(&secretContext.GatewayID); err != nil {
		return secret.Context{}, secret.Envelope{}, fmt.Errorf("load envelope gateway ID: %w", err)
	}
	envelope.KeyVersion = uint32(keyVersion)
	envelope.AADVersion = uint32(aadVersion)
	return secretContext, envelope, nil
}

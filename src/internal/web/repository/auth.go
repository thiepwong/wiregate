// File: src/internal/web/repository/auth.go
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
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         string
	Status       string
	LockedUntil  time.Time
}

type Session struct {
	User        User
	CSRFHash    []byte
	ReauthUntil time.Time
}

func (r *Repository) BootstrapRequired(ctx context.Context) (bool, error) {
	var users int
	if err := r.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return false, err
	}
	return users == 0, nil
}

func (r *Repository) SetBootstrapToken(ctx context.Context, tokenHash []byte, expiresAt, now time.Time) error {
	if len(tokenHash) != 32 || !expiresAt.After(now) {
		return errors.New("invalid bootstrap token or expiry")
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var users int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return err
	}
	if users != 0 {
		return errors.New("bootstrap is disabled after the first user")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO bootstrap_state(singleton_id, token_hash, expires_at_ms, created_at_ms)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(singleton_id) DO UPDATE SET
			token_hash = excluded.token_hash,
			expires_at_ms = excluded.expires_at_ms,
			consumed_at_ms = NULL,
			created_at_ms = excluded.created_at_ms`,
		tokenHash, expiresAt.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) BootstrapAdmin(
	ctx context.Context,
	tokenHash []byte,
	username, displayName, passwordHash, requestID string,
	now time.Time,
) (User, error) {
	if username == "" || displayName == "" || passwordHash == "" {
		return User{}, errors.New("bootstrap user fields are required")
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var users int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return User{}, err
	}
	if users != 0 {
		return User{}, errors.New("bootstrap is no longer available")
	}
	var stored []byte
	var expiresAt int64
	var consumed sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT token_hash, expires_at_ms, consumed_at_ms
		FROM bootstrap_state WHERE singleton_id = 1`,
	).Scan(&stored, &expiresAt, &consumed); err != nil {
		return User{}, errors.New("bootstrap token is invalid")
	}
	if consumed.Valid || expiresAt <= now.UnixMilli() ||
		len(stored) != len(tokenHash) || subtle.ConstantTimeCompare(stored, tokenHash) != 1 {
		return User{}, errors.New("bootstrap token is invalid")
	}
	id, err := ids.NewV7(now)
	if err != nil {
		return User{}, err
	}
	user := User{
		ID: id, Username: username, DisplayName: displayName,
		PasswordHash: passwordHash, Role: "admin", Status: "active",
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users(
			id, username, display_name, password_hash, role, status,
			password_changed_ms, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, 'admin', 'active', ?, ?, ?)`,
		id, username, displayName, passwordHash,
		now.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return User{}, fmt.Errorf("create bootstrap admin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE bootstrap_state SET consumed_at_ms = ?
		WHERE singleton_id = 1 AND consumed_at_ms IS NULL`, now.UnixMilli(),
	); err != nil {
		return User{}, err
	}
	auditID, err := ids.NewV7(now.Add(time.Nanosecond))
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO web_audit_events(
			id, actor_user_id, action, target_type, target_id,
			request_id, result, created_at_ms
		) VALUES (?, ?, 'bootstrap_admin', 'user', ?, ?, 'success', ?)`,
		auditID, id, id, requestID, now.UnixMilli(),
	); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *Repository) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	var locked sql.NullInt64
	err := r.database.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, role, status, locked_until_ms
		FROM users WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username),
	).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash,
		&user.Role, &user.Status, &locked,
	)
	if locked.Valid {
		user.LockedUntil = time.UnixMilli(locked.Int64).UTC()
	}
	return user, err
}

func (r *Repository) CreateSession(
	ctx context.Context,
	userID string,
	idHash, csrfHash []byte,
	expiresAt, idleExpiresAt, now time.Time,
) error {
	_, err := r.database.ExecContext(ctx, `
		INSERT INTO sessions(
			id_hash, user_id, csrf_hash, expires_at_ms, idle_expires_at_ms,
			last_seen_at_ms, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		idHash, userID, csrfHash, expiresAt.UnixMilli(), idleExpiresAt.UnixMilli(),
		now.UnixMilli(), now.UnixMilli(),
	)
	return err
}

func (r *Repository) GetSession(ctx context.Context, idHash []byte, now time.Time) (Session, error) {
	var session Session
	var locked, reauthUntil sql.NullInt64
	err := r.database.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.display_name, u.password_hash, u.role, u.status,
		       u.locked_until_ms, s.csrf_hash, s.reauth_until_ms
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = ? AND s.revoked_at_ms IS NULL
		  AND s.expires_at_ms > ? AND s.idle_expires_at_ms > ?
		  AND u.status = 'active'`,
		idHash, now.UnixMilli(), now.UnixMilli(),
	).Scan(
		&session.User.ID, &session.User.Username, &session.User.DisplayName,
		&session.User.PasswordHash, &session.User.Role, &session.User.Status,
		&locked, &session.CSRFHash, &reauthUntil,
	)
	if err != nil {
		return Session{}, err
	}
	if locked.Valid && locked.Int64 > now.UnixMilli() {
		return Session{}, errors.New("user is locked")
	}
	if reauthUntil.Valid {
		session.ReauthUntil = time.UnixMilli(reauthUntil.Int64).UTC()
	}
	_, _ = r.database.ExecContext(ctx, `
		UPDATE sessions
		SET last_seen_at_ms = ?, idle_expires_at_ms = MIN(expires_at_ms, ?)
		WHERE id_hash = ?`,
		now.UnixMilli(), now.Add(30*time.Minute).UnixMilli(), idHash,
	)
	return session, nil
}

func (r *Repository) MarkReauthenticated(ctx context.Context, idHash []byte, until time.Time) error {
	result, err := r.database.ExecContext(ctx, `
		UPDATE sessions SET reauth_until_ms = ?
		WHERE id_hash = ? AND revoked_at_ms IS NULL`, until.UnixMilli(), idHash,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("session is unavailable")
	}
	return nil
}

func (r *Repository) ChangePassword(
	ctx context.Context,
	userID string,
	currentSessionHash []byte,
	passwordHash string,
	now time.Time,
) error {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, password_changed_ms = ?, updated_at_ms = ?
		WHERE id = ? AND status = 'active'`, passwordHash, now.UnixMilli(), now.UnixMilli(), userID,
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("user is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at_ms = ?
		WHERE user_id = ? AND id_hash <> ? AND revoked_at_ms IS NULL`,
		now.UnixMilli(), userID, currentSessionHash,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE sessions SET reauth_until_ms = ? WHERE id_hash = ? AND revoked_at_ms IS NULL`,
		now.Add(5*time.Minute).UnixMilli(), currentSessionHash,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetAdminPassword performs physical-console recovery for an administrator.
// The caller is responsible for stopping the web runtime so a login cannot
// race the password update and session revocation transaction.
func (r *Repository) ResetAdminPassword(
	ctx context.Context,
	username, passwordHash string,
	now time.Time,
) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" || passwordHash == "" {
		return "", errors.New("admin username and password hash are required")
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var userID, storedUsername string
	if err := tx.QueryRowContext(ctx, `
		SELECT id, username FROM users
		WHERE username = ? COLLATE NOCASE AND role = 'admin'`, username,
	).Scan(&userID, &storedUsername); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("admin user not found")
		}
		return "", err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE users
		SET password_hash = ?, status = 'active', failed_login_count = 0,
		    locked_until_ms = NULL, password_changed_ms = ?, updated_at_ms = ?
		WHERE id = ? AND role = 'admin'`,
		passwordHash, now.UnixMilli(), now.UnixMilli(), userID,
	)
	if err != nil {
		return "", err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return "", errors.New("admin user is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at_ms = ?
		WHERE user_id = ? AND revoked_at_ms IS NULL`, now.UnixMilli(), userID,
	); err != nil {
		return "", err
	}
	auditID, err := ids.NewV7(now)
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO web_audit_events(
			id, actor_user_id, action, target_type, target_id,
			request_id, result, details_redacted, created_at_ms
		) VALUES (?, NULL, 'reset_admin_password_cli', 'user', ?, ?,
		          'success', 'physical host recovery', ?)`,
		auditID, userID, "cli-"+auditID, now.UnixMilli(),
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return storedUsername, nil
}

func (r *Repository) RevokeSession(ctx context.Context, idHash []byte, now time.Time) error {
	_, err := r.database.ExecContext(ctx, `
		UPDATE sessions SET revoked_at_ms = ? WHERE id_hash = ? AND revoked_at_ms IS NULL`,
		now.UnixMilli(), idHash,
	)
	return err
}

func (r *Repository) RecordLoginFailure(
	ctx context.Context,
	username, requestID, sourceIP string,
	now time.Time,
) error {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID sql.NullString
	_ = tx.QueryRowContext(ctx, `
		SELECT id FROM users WHERE username = ? COLLATE NOCASE`, username,
	).Scan(&userID)
	if userID.Valid {
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET failed_login_count = failed_login_count + 1,
			    locked_until_ms = CASE
			      WHEN failed_login_count + 1 >= 5 THEN ?
			      ELSE locked_until_ms
			    END,
			    updated_at_ms = ?
			WHERE id = ?`,
			now.Add(15*time.Minute).UnixMilli(), now.UnixMilli(), userID.String,
		); err != nil {
			return err
		}
	}
	if err := insertLoginEvent(ctx, tx, userID, username, "failure", sourceIP, requestID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) RecordLoginSuccess(
	ctx context.Context,
	userID, username, requestID, sourceIP string,
	now time.Time,
) error {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET failed_login_count = 0, locked_until_ms = NULL, updated_at_ms = ?
		WHERE id = ?`, now.UnixMilli(), userID,
	); err != nil {
		return err
	}
	if err := insertLoginEvent(
		ctx, tx, sql.NullString{String: userID, Valid: true},
		username, "success", sourceIP, requestID, now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func insertLoginEvent(
	ctx context.Context,
	tx *sql.Tx,
	userID sql.NullString,
	username, result, sourceIP, requestID string,
	now time.Time,
) error {
	id, err := ids.NewV7(now)
	if err != nil {
		return err
	}
	var user any
	if userID.Valid {
		user = userID.String
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO login_events(
			id, user_id, username_normalized, result, source_ip, request_id, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, user, strings.ToLower(username), result, nullableWeb(sourceIP), requestID, now.UnixMilli(),
	); err != nil {
		return err
	}
	return nil
}

func nullableWeb(value string) any {
	if value == "" {
		return nil
	}
	return value
}

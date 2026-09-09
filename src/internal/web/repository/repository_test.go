// File: src/internal/web/repository/repository_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAppliesWebMigrations(t *testing.T) {
	repository, err := Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer repository.Close()
	if repository.SchemaVersion() != 1 {
		t.Fatalf("SchemaVersion() = %d", repository.SchemaVersion())
	}
}

func TestResetAdminPasswordUnlocksAdminAndRevokesSessions(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 9, 8, 0, 0, 0, time.UTC)
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	tokenHash := bytes.Repeat([]byte{1}, 32)
	if err := repository.SetBootstrapToken(ctx, tokenHash, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	user, err := repository.BootstrapAdmin(
		ctx, tokenHash, "admin", "Administrator", "old-password-hash", "bootstrap-request", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionHash := bytes.Repeat([]byte{2}, 32)
	if err := repository.CreateSession(
		ctx, user.ID, sessionHash, bytes.Repeat([]byte{3}, 32),
		now.Add(time.Hour), now.Add(30*time.Minute), now,
	); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if err := repository.RecordLoginFailure(
			ctx, user.Username, "failure-request", "127.0.0.1", now,
		); err != nil {
			t.Fatal(err)
		}
	}
	lockedUser, err := repository.FindUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !lockedUser.LockedUntil.After(now) {
		t.Fatal("admin was not locked after five failed logins")
	}

	storedUsername, err := repository.ResetAdminPassword(
		ctx, "ADMIN", "new-password-hash", now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if storedUsername != "admin" {
		t.Fatalf("stored username = %q", storedUsername)
	}
	resetUser, err := repository.FindUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if resetUser.PasswordHash != "new-password-hash" || resetUser.Status != "active" ||
		!resetUser.LockedUntil.IsZero() {
		t.Fatalf("reset user = %+v", resetUser)
	}
	if _, err := repository.GetSession(ctx, sessionHash, now.Add(time.Minute)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old session remains usable: %v", err)
	}
	var action, details string
	if err := repository.database.QueryRowContext(ctx, `
		SELECT action, details_redacted FROM web_audit_events
		WHERE action = 'reset_admin_password_cli' AND target_id = ?`, user.ID,
	).Scan(&action, &details); err != nil {
		t.Fatal(err)
	}
	if action != "reset_admin_password_cli" || details != "physical host recovery" {
		t.Fatalf("recovery audit = %q, %q", action, details)
	}
}

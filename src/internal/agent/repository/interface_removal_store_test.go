// File: src/internal/agent/repository/interface_removal_store_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-09-09
// Description: WireGate automated tests.

package repository

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
)

func TestFinalizeManagedInterfaceRemovalDeletesOwnedStateAndKeepsHistory(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	interfaceID := "managed-interface"
	if _, err := store.database.ExecContext(ctx, `
		INSERT INTO interfaces(
			id, name, backend, namespace_kind, management_mode, config_path,
			service_owner, service_unit, config_present, runtime_present,
			file_hash, runtime_fingerprint, revision, drift_state,
			deployment_profile, firewall_mode, managed_firewall_backend,
			listen_port, public_key, auto_start, service_state,
			last_seen_at_ms, created_at_ms, updated_at_ms
		) VALUES (?, 'wg0', 'wg_quick', 'host', 'managed', '/etc/wireguard/wg0.conf',
		          'systemd', 'wg-quick@wg0.service', 1, 1, 'file-hash',
		          'runtime-hash', 3, 'none', 'server_only', 'external', 'none',
		          51820, 'server-public-key', 1, 'active', ?, ?, ?)`,
		interfaceID, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		t.Fatal(err)
	}
	history, err := store.CreateOperation(ctx, CreateOperationInput{
		InterfaceID: interfaceID, Type: "create_interface", IntentJSON: `{ "name": "wg0" }`,
		IdempotencyKey: "create-history", ActorID: "admin", ActorRole: "admin",
		RequestID: "create-request", Reason: "create test interface",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.ExecContext(ctx, `
		UPDATE operations SET state = 'committed', finished_at_ms = ? WHERE id = ?`,
		now.UnixMilli(), history.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.ExecContext(ctx, `
		INSERT INTO managed_resources(
			id, interface_id, operation_id, resource_kind, path, fingerprint, created_at_ms
		) VALUES ('resource-config', ?, ?, 'wireguard_config',
		          '/etc/wireguard/wg0.conf', 'file-hash', ?)`,
		interfaceID, history.ID, now.UnixMilli(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.ExecContext(ctx, `
		INSERT INTO peers(
			id, interface_id, name, public_key, key_mode, lifecycle_state,
			persistent_keepalive, observed_present, last_seen_at_ms, created_at_ms, updated_at_ms
		) VALUES ('peer-one', ?, 'laptop', 'peer-public-key', 'managed', 'active',
		          25, 1, ?, ?, ?)`,
		interfaceID, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		t.Fatal(err)
	}
	for _, secretOwner := range []struct{ ownerType, ownerID, purpose string }{
		{"peer", "peer-one", "client_private_key"},
		{"operation", history.ID, "snapshot_payload"},
	} {
		if _, err := store.database.ExecContext(ctx, `
			INSERT INTO secret_envelopes(
				id, owner_type, owner_id, purpose, algorithm, ciphertext,
				payload_nonce, wrapped_dek, wrap_nonce, key_version, aad_version,
				created_at_ms, updated_at_ms
			) VALUES (? || '-secret', ?, ?, ?, 'test', X'01', X'02', X'03', X'04', 1, 1, ?, ?)`,
			secretOwner.ownerID, secretOwner.ownerType, secretOwner.ownerID,
			secretOwner.purpose, now.UnixMilli(), now.UnixMilli(),
		); err != nil {
			t.Fatal(err)
		}
	}

	expectedRevision := int64(3)
	removal, err := store.CreateOperation(ctx, CreateOperationInput{
		InterfaceID: interfaceID, Type: "set_interface_state",
		IntentJSON:     `{ "interface_id": "managed-interface", "desired_state": "removed" }`,
		IdempotencyKey: "remove-interface", ActorID: "admin", ActorRole: "admin",
		RequestID: "remove-request", Reason: "reset the test interface",
		ExpectedRevision: &expectedRevision, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []struct {
		from agentoperation.State
		to   agentoperation.State
	}{
		{agentoperation.StatePending, agentoperation.StateValidated},
		{agentoperation.StateValidated, agentoperation.StateSnapshotted},
		{agentoperation.StateSnapshotted, agentoperation.StateExecuting},
		{agentoperation.StateExecuting, agentoperation.StateVerifying},
	} {
		if err := store.TransitionOperation(ctx, removal.ID, transition.from, transition.to, nil); err != nil {
			t.Fatal(err)
		}
	}

	revision, peerCount, err := store.FinalizeManagedInterfaceRemoval(ctx, removal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revision != expectedRevision || peerCount != 1 {
		t.Fatalf("revision=%d peers=%d", revision, peerCount)
	}
	for _, check := range []struct {
		name  string
		query string
		args  []any
	}{
		{"interface", `SELECT COUNT(*) FROM interfaces WHERE id = 'managed-interface'`, nil},
		{"peer", `SELECT COUNT(*) FROM peers WHERE id = 'peer-one'`, nil},
		{"resource", `SELECT COUNT(*) FROM managed_resources WHERE interface_id = 'managed-interface'`, nil},
		{"owned secrets", `SELECT COUNT(*) FROM secret_envelopes WHERE owner_id IN ('peer-one', ?)`, []any{history.ID}},
	} {
		var count int
		if err := store.database.QueryRowContext(ctx, check.query, check.args...).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s count = %d", check.name, count)
		}
	}
	var retained, attached int
	if err := store.database.QueryRowContext(ctx, `
		SELECT COUNT(*), COUNT(interface_id) FROM operations WHERE id IN (?, ?)`,
		history.ID, removal.ID,
	).Scan(&retained, &attached); err != nil {
		t.Fatal(err)
	}
	if retained != 2 || attached != 0 {
		t.Fatalf("retained operations=%d attached=%d", retained, attached)
	}
	committed, err := store.GetOperation(ctx, removal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != agentoperation.StateCommitted {
		t.Fatalf("removal state = %s", committed.State)
	}
	var audits int
	if err := store.database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE operation_id = ? AND action = 'remove_interface' AND result = 'success'`,
		removal.ID,
	).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("remove-interface audit count = %d", audits)
	}
}

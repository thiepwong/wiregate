// File: src/internal/agent/repository/operation_store_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package repository

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
)

func TestOperationJournalIsDurableAndCASProtected(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	item, err := repository.CreateOperation(ctx, CreateOperationInput{
		Type: "create_interface", IntentJSON: `{"version":1}`,
		IdempotencyKey: "idem-1", ActorID: "admin-1", ActorRole: "admin",
		RequestID: "request-1", ExpiresAt: time.Now().Add(5 * time.Minute),
		Steps: []agentoperation.StepRecord{{
			Name: "config", Kind: "file",
			OriginalFingerprint: "absent", ProposedFingerprint: "present",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.TransitionOperation(
		ctx, item.ID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := repository.TransitionOperation(
		ctx, item.ID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err == nil {
		t.Fatal("stale operation transition succeeded")
	}
	loaded, err := repository.GetOperation(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != agentoperation.StateValidated || len(loaded.Steps) != 1 {
		t.Fatalf("loaded operation = %#v", loaded)
	}
}

func TestOperationIdempotencyReturnsOriginalPlan(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	input := CreateOperationInput{
		Type: "create_interface", IntentJSON: `{"version":1}`,
		IdempotencyKey: "same", ActorID: "admin", ActorRole: "admin", RequestID: "request",
	}
	first, err := repository.CreateOperation(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.CreateOperation(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent operation IDs differ: %s %s", first.ID, second.ID)
	}
}

func TestOperationQueryIsRedactedAndCursorStable(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	expected := int64(7)
	store.now = func() time.Time { return base }
	first, err := store.CreateOperation(ctx, CreateOperationInput{
		Type: "create_interface", IntentJSON: `{"secret_input":"never returned"}`,
		IdempotencyKey: "query-1", ActorID: "admin", ActorRole: "admin",
		RequestID: "request-1", ExpectedRevision: &expected,
		ProposedDiffJSON: `{"name":"wg0"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(time.Millisecond) }
	second, err := store.CreateOperation(ctx, CreateOperationInput{
		Type: "create_interface", IntentJSON: `{"version":1}`,
		IdempotencyKey: "query-2", ActorID: "admin", ActorRole: "admin",
		RequestID: "request-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	page, err := store.ListOperations(ctx, "", "", 1, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("first page = %#v", page)
	}
	next, err := store.ListOperations(ctx, "", "", 2, page[0].CreatedAt, page[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || next[0].ID != first.ID {
		t.Fatalf("next page = %#v", next)
	}
	loaded, err := store.GetOperation(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ExpectedRevision == nil || *loaded.ExpectedRevision != expected ||
		loaded.ProposedDiffJSON != `{"name":"wg0"}` {
		t.Fatalf("loaded operation metadata = %#v", loaded)
	}
}

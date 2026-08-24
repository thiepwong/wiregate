// File: src/internal/agent/artifact/service_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package artifact_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/artifact"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

const gatewayID = "01900000-0000-7000-8000-000000000001"

func TestOneTimeArtifactCannotBeReused(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "agent.db"), gatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	master := bytes.Repeat([]byte{7}, 32)
	service, err := artifact.NewService(store, func(uint32) ([]byte, error) {
		return append([]byte(nil), master...), nil
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	secretContext := secret.Context{
		GatewayID: gatewayID, OwnerType: "artifact", OwnerID: "artifact-owner",
		Purpose: "one_time_payload",
	}
	_, token, err := service.Create(ctx, testPeer(t, ctx, store), secretContext, []byte("one time"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var received []byte
	if err := service.Consume(ctx, token, func(body []byte) error {
		received = append([]byte(nil), body...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if string(received) != "one time" {
		t.Fatalf("received = %q", received)
	}
	if err := service.Consume(ctx, token, func([]byte) error { return nil }); err == nil {
		t.Fatal("one-time artifact was reused")
	}
}

func testPeer(t *testing.T, ctx context.Context, store *repository.Repository) string {
	t.Helper()
	// Inventory insertion creates a valid external peer without exposing any
	// secret in the repository.
	_, err := store.ReplaceInventory(ctx, inventorySnapshot())
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := store.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := store.ListPeers(ctx, interfaces[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return peers[0].ID
}

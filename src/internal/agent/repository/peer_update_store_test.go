// File: src/internal/agent/repository/peer_update_store_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

func TestAdoptedPeerUpdateMovesAllocationAndPreservesExternalProfile(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	_, err = store.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ConfigPresent: true,
			FileHash: "before", DriftState: "none",
			Addresses: []inventory.Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []inventory.Peer{{
				Name: "old-peer", PublicKey: publicKey, AllowedIPs: []string{"10.0.0.2/32"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, _ := store.ListInterfaces(ctx)
	interfaceID := interfaces[0].ID
	expected := int64(0)
	adoptionOperation, err := store.CreateOperation(ctx, CreateOperationInput{
		InterfaceID: interfaceID, Type: "adopt_interface", IntentJSON: `{}`,
		IdempotencyKey: "adopt", ActorID: "admin", ActorRole: "admin", RequestID: "adopt-request",
		ExpectedRevision: &expected, OriginalFileHash: "before",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotForRepositoryTest(ctx, store, adoptionOperation.ID, interfaceID, "before"); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionOperation(ctx, adoptionOperation.ID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyAdoption(ctx, adoptionOperation.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeAdoption(ctx, adoptionOperation.ID); err != nil {
		t.Fatal(err)
	}
	peers, _ := store.ListPeers(ctx, interfaceID)
	material, err := store.ClientMaterial(ctx, peers[0].ID)
	if err != nil || material.ProfileState != "external" {
		t.Fatalf("external profile = %#v, err = %v", material, err)
	}

	expected = 1
	updateOperation, err := store.CreateOperation(ctx, CreateOperationInput{
		InterfaceID: interfaceID, Type: "update_peer", IntentJSON: `{}`,
		IdempotencyKey: "update", ActorID: "admin", ActorRole: "admin", RequestID: "update-request",
		ExpectedRevision: &expected, OriginalFileHash: "before",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotForRepositoryTest(ctx, store, updateOperation.ID, interfaceID, "before"); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionOperation(ctx, updateOperation.ID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil); err != nil {
		t.Fatal(err)
	}
	revision, err := store.CompletePeerUpdate(ctx, updateOperation.ID, PeerUpdateInput{
		PeerID: peers[0].ID, InterfaceID: interfaceID, Name: "renamed",
		Endpoint: "client.example:51820", PersistentKeepalive: 25,
		AllowedIPs:   []string{"10.0.0.3/32", "192.168.50.0/24"},
		ClientRoutes: []string{"10.0.0.0/24"}, OriginalFileHash: "before",
		ProposedFileHash: "after", RuntimeFingerprint: "runtime-after",
	})
	if err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("revision = %d", revision)
	}
	updated, err := store.GetPeer(ctx, peers[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed" || updated.Endpoint != "client.example:51820" ||
		len(updated.AllowedIPs) != 2 {
		t.Fatalf("updated peer = %#v", updated)
	}
	next, err := store.NextAvailableAddress(ctx, interfaceID)
	if err != nil || next.Prefix != "10.0.0.4/32" {
		t.Fatalf("next address after update = %#v, err = %v", next, err)
	}
}

func snapshotForRepositoryTest(
	ctx context.Context,
	store *Repository,
	operationID, interfaceID, fileHash string,
) error {
	if err := store.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return err
	}
	secretContext := secret.Context{
		GatewayID: testGatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload",
	}
	envelope, err := secret.Seal(
		bytes.Repeat([]byte{9}, 32), 1, secretContext, []byte("snapshot"), nil,
	)
	if err != nil {
		return err
	}
	return store.SnapshotOperation(
		ctx, operationID, secretContext, envelope, fileHash, "", nil,
	)
}

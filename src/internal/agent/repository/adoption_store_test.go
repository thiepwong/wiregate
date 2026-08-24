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

func TestRollbackAdoptionDeletesStagedSecretsBeforeTheyBecomeAuthoritative(t *testing.T) {
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
			Name: "wg0", Backend: "wg_quick", ManagementMode: "observed",
			ConfigPresent: true, FileHash: "file-hash",
			Addresses: []inventory.Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []inventory.Peer{{
				Name: "peer", PublicKey: publicKey, AllowedIPs: []string{"10.0.0.2/32"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, _ := store.ListInterfaces(ctx)
	peers, _ := store.ListPeers(ctx, interfaces[0].ID)
	expectedRevision := int64(0)
	operationRecord, err := store.CreateOperation(ctx, CreateOperationInput{
		InterfaceID: interfaces[0].ID, Type: "adopt_interface",
		IntentJSON: `{"version":1}`, IdempotencyKey: "staged-rollback",
		ActorID: "admin", ActorRole: "admin", RequestID: "request",
		ExpectedRevision: &expectedRevision, OriginalFileHash: "file-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionOperation(
		ctx, operationRecord.ID, agentoperation.StatePending,
		agentoperation.StateValidated, nil,
	); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{9}, 32)
	snapshotContext := secret.Context{
		GatewayID: testGatewayID, OwnerType: "operation",
		OwnerID: operationRecord.ID, Purpose: "snapshot_payload",
	}
	snapshotEnvelope, err := secret.Seal(
		master, 1, snapshotContext, []byte("config bytes"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	pskContext := secret.Context{
		GatewayID: testGatewayID, OwnerType: "peer",
		OwnerID: peers[0].ID, Purpose: "preshared_key",
	}
	pskEnvelope, err := secret.Seal(
		master, 1, pskContext, bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SnapshotOperation(
		ctx, operationRecord.ID, snapshotContext, snapshotEnvelope,
		"file-hash", "", []StoredSecretInput{{
			Context: pskContext, Envelope: pskEnvelope,
		}},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionOperation(
		ctx, operationRecord.ID, agentoperation.StateSnapshotted,
		agentoperation.StateRollingBack, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.RollbackAdoption(ctx, operationRecord.ID); err != nil {
		t.Fatal(err)
	}
	var staged, profiles, pskEnvelopes int
	if err := store.database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM operation_staged_secrets WHERE operation_id = ?`,
		operationRecord.ID,
	).Scan(&staged); err != nil {
		t.Fatal(err)
	}
	if err := store.database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM client_profiles WHERE peer_id = ?`,
		peers[0].ID,
	).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if err := store.database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM secret_envelopes
		WHERE owner_type = 'peer' AND owner_id = ? AND purpose = 'preshared_key'`,
		peers[0].ID,
	).Scan(&pskEnvelopes); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetOperation(ctx, operationRecord.ID)
	if err != nil {
		t.Fatal(err)
	}
	if staged != 0 || profiles != 0 || pskEnvelopes != 0 ||
		recovered.State != agentoperation.StateRolledBack {
		t.Fatalf(
			"rollback state=%s staged=%d profiles=%d psk_envelopes=%d",
			recovered.State, staged, profiles, pskEnvelopes,
		)
	}
}

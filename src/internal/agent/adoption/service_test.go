// File: src/internal/agent/adoption/service_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package adoption

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

const testGateway = "01900000-0000-7000-8000-000000000001"

type fakeFiles struct {
	config filesystem.ConfigFile
	atomic error
}

func (f fakeFiles) ReadConfig(string) (filesystem.ConfigFile, error) {
	result := f.config
	result.Body = bytes.Clone(f.config.Body)
	return result, nil
}
func (f fakeFiles) SupportsAtomicExchange() error { return f.atomic }

type failFinalizeRepository struct {
	*repository.Repository
	failed bool
}

func (r *failFinalizeRepository) FinalizeAdoption(ctx context.Context, operationID string) error {
	if !r.failed {
		r.failed = true
		return errors.New("injected crash before finalize")
	}
	return r.Repository.FinalizeAdoption(ctx, operationID)
}

func TestPreviewAndCommitAdoptionDoesNotRewriteConfig(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGateway)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	body := []byte("# retained\n[Interface]\nPrivateKey = " + private + "\n\n[Peer]\nPublicKey = " + public + "\nPresharedKey = " + psk + "\nAllowedIPs = 10.0.0.2/32\n")
	hash := filesystem.SHA256(body)
	_, err = store.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ManagementMode: "observed",
			ConfigPath: "/etc/wireguard/wg0.conf", ConfigPresent: true,
			FileHash: hash, DriftState: "none",
			Addresses: []inventory.Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []inventory.Peer{{
				Name: "peer", PublicKey: public, AllowedIPs: []string{"10.0.0.2/32"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := store.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(
		store,
		fakeFiles{config: filesystem.ConfigFile{Body: body, Hash: hash}},
		func(uint32) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil },
		func() ([]byte, error) { return bytes.Repeat([]byte{8}, 32), nil },
		testGateway, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{
		ID: "admin", Role: "admin", RequestID: "request",
		Permission: "interface:adopt", IdempotencyKey: "idempotency",
	}
	preview, err := service.Preview(ctx, interfaces[0].ID, 0, actor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Commit(ctx, preview.OperationID, actor)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "committed" || result.InterfaceRevision != 1 {
		t.Fatalf("result = %#v", result)
	}
	updated, err := store.GetInterface(ctx, interfaces[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ManagementMode != "adopted" || updated.FileHash != hash {
		t.Fatalf("updated interface = %#v", updated)
	}
	peers, err := store.ListPeers(ctx, interfaces[0].ID)
	if err != nil || len(peers) != 1 {
		t.Fatalf("adopted peers = %#v, err = %v", peers, err)
	}
	material, err := store.ClientMaterial(ctx, peers[0].ID)
	if err != nil || material.ProfileState != "external" || material.PresharedKey == nil {
		t.Fatalf("adopted external profile = %#v, err = %v", material, err)
	}
	openedPSK, err := secret.Open(
		bytes.Repeat([]byte{9}, 32), material.PresharedKey.Context, material.PresharedKey.Envelope,
	)
	if err != nil || string(openedPSK) != psk {
		t.Fatalf("adopted PSK canonical form mismatch, err = %v", err)
	}
	clear(openedPSK)
	next, err := store.NextAvailableAddress(ctx, interfaces[0].ID)
	if err != nil || next.Prefix != "10.0.0.3/32" {
		t.Fatalf("next adopted address = %#v, err = %v", next, err)
	}

	fingerprint, err := secret.Fingerprint(
		bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{4}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ConfigPresent: true,
			FileHash: filesystem.SHA256(append(body, '#')), DriftState: "file",
			Addresses: []inventory.Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []inventory.Peer{{
				Name: "peer", PublicKey: public, AllowedIPs: []string{"10.0.0.2/32"},
				PSKPresent: true, PSKFingerprint: fingerprint,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	drifted, err := store.GetInterface(ctx, interfaces[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if drifted.DriftState != "secret" {
		t.Fatalf("CLI PSK change drift = %s", drifted.DriftState)
	}
}

func TestRecoveryFinalizesAdoptionAfterCrashInVerifying(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGateway)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	body := []byte("[Interface]\nPrivateKey = " + private +
		"\n\n[Peer]\nPublicKey = " + public +
		"\nPresharedKey = " + psk + "\nAllowedIPs = 10.0.0.2/32\n")
	hash := filesystem.SHA256(body)
	_, err = store.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ManagementMode: "observed",
			ConfigPath: "/etc/wireguard/wg0.conf", ConfigPresent: true,
			FileHash: hash, DriftState: "none",
			Addresses: []inventory.Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []inventory.Peer{{
				Name: "peer", PublicKey: public, AllowedIPs: []string{"10.0.0.2/32"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, _ := store.ListInterfaces(ctx)
	files := fakeFiles{config: filesystem.ConfigFile{Body: body, Hash: hash}}
	masterKey := func(uint32) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
	fingerprintKey := func() ([]byte, error) { return bytes.Repeat([]byte{8}, 32), nil }
	crashingStore := &failFinalizeRepository{Repository: store}
	service, err := New(
		crashingStore, files, masterKey, fingerprintKey, testGateway, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{
		ID: "admin", Role: "admin", RequestID: "request",
		Permission: "interface:adopt", IdempotencyKey: "crash-recovery",
	}
	preview, err := service.Preview(ctx, interfaces[0].ID, 0, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Commit(ctx, preview.OperationID, actor); err == nil {
		t.Fatal("injected finalize crash did not interrupt commit")
	}
	interrupted, err := store.GetOperation(ctx, preview.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.State != "verifying" {
		t.Fatalf("interrupted operation state = %s", interrupted.State)
	}

	recoveredService, err := New(
		store, files, masterKey, fingerprintKey, testGateway, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoveredService.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetOperation(ctx, preview.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != "committed" {
		t.Fatalf("recovered operation state = %s", recovered.State)
	}
}

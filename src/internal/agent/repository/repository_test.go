package repository

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

const testGatewayID = "01900000-0000-7000-8000-000000000001"

func TestRepositoryPersistsRedactedInventory(t *testing.T) {
	ctx := context.Background()
	repository, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"), testGatewayID)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer repository.Close()

	refreshedAt := time.Unix(1_700_000_000, 0).UTC()
	_, err = repository.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: refreshedAt,
		Interfaces: []inventory.Interface{{
			Name:               "wg0",
			Backend:            "wg_quick",
			ConfigPath:         "/etc/wireguard/wg0.conf",
			ConfigPresent:      true,
			RuntimePresent:     true,
			FileHash:           "file",
			RuntimeFingerprint: "runtime",
			DriftState:         "unknown",
			Addresses: []inventory.Address{{
				Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file",
			}},
			Peers: []inventory.Peer{{
				Name:              "external-peer",
				PublicKey:         "public",
				AllowedIPs:        []string{"10.0.0.2/32"},
				Endpoint:          "198.51.100.2:51820",
				LatestHandshakeAt: refreshedAt.Add(-time.Minute),
				TransferRXBytes:   12,
				TransferTXBytes:   34,
				RuntimeSeenAt:     refreshedAt,
				ActivityState:     "active",
			}},
		}},
	})
	if err != nil {
		t.Fatalf("ReplaceInventory() error = %v", err)
	}

	interfaces, err := repository.ListInterfaces(ctx)
	if err != nil {
		t.Fatalf("ListInterfaces() error = %v", err)
	}
	if len(interfaces) != 1 || interfaces[0].PeerCount != 1 || len(interfaces[0].Addresses) != 1 {
		t.Fatalf("interfaces = %#v", interfaces)
	}
	peers, err := repository.ListPeers(ctx, interfaces[0].ID)
	if err != nil {
		t.Fatalf("ListPeers() error = %v", err)
	}
	if len(peers) != 1 || peers[0].AllowedIPs[0] != "10.0.0.2/32" || peers[0].TransferTXBytes != 34 {
		t.Fatalf("peers = %#v", peers)
	}
}

func TestRepositoryRejectsDifferentGateway(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	first, err := Open(ctx, path, testGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, "01900000-0000-7000-8000-000000000002"); err == nil {
		t.Fatal("Open() accepted a database owned by another gateway")
	}
}

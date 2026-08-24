// File: src/internal/agent/inventory/service_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package inventory

import (
	"context"
	"testing"
	"time"
)

type fakeFiles struct {
	records []FileRecord
}

func (f fakeFiles) Scan(context.Context) ([]FileRecord, []DiagnosticIssue, error) {
	return f.records, nil, nil
}

type fakeRuntime struct {
	records []RuntimeRecord
}

func (f fakeRuntime) List(context.Context) ([]RuntimeRecord, error) {
	return f.records, nil
}

type fakeAddresses struct {
	records map[string][]Address
}

func (f fakeAddresses) List(context.Context, []string) (map[string][]Address, error) {
	return f.records, nil
}

type captureStore struct {
	snapshot Snapshot
}

func (s *captureStore) ReplaceInventory(_ context.Context, snapshot Snapshot) (PersistResult, error) {
	s.snapshot = snapshot
	peers := 0
	for _, record := range snapshot.Interfaces {
		peers += len(record.Peers)
	}
	return PersistResult{InterfaceCount: len(snapshot.Interfaces), PeerCount: peers}, nil
}

func TestRefreshMergesFileAndRuntimeWithoutDroppingFileOnlyPeer(t *testing.T) {
	const fileOnlyKey = "file-only"
	const runtimeKey = "runtime"
	store := &captureStore{}
	service := NewService(
		fakeFiles{records: []FileRecord{{Interface: Interface{
			Name:          "wg0",
			Backend:       "wg_quick",
			ConfigPresent: true,
			FileHash:      "file-hash",
			DriftState:    "none",
			Addresses:     []Address{{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "file"}},
			Peers: []Peer{
				{Name: "declared", PublicKey: fileOnlyKey, AllowedIPs: []string{"10.0.0.2/32"}},
				{Name: "named-in-file", PublicKey: runtimeKey, AllowedIPs: []string{"10.0.0.3/32"}},
			},
		}}}},
		fakeRuntime{records: []RuntimeRecord{{Interface: Interface{
			Name:               "wg0",
			Backend:            "runtime_only",
			RuntimePresent:     true,
			RuntimeFingerprint: "runtime-hash",
			Peers: []Peer{{
				Name:            "external-runtime",
				PublicKey:       runtimeKey,
				AllowedIPs:      []string{"10.0.0.3/32"},
				TransferRXBytes: 42,
				RuntimeSeenAt:   time.Unix(100, 0),
				ActivityState:   "active",
			}},
		}}}},
		fakeAddresses{records: map[string][]Address{
			"wg0": {
				{Family: 4, Address: "10.0.0.1", PrefixLength: 24, Source: "runtime"},
				{Family: 6, Address: "fd00::1", PrefixLength: 64, Source: "runtime"},
			},
		}},
		store,
		func(name string) bool { return name == "wg0" },
	)

	result, err := service.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if result.InterfaceCount != 1 || result.PeerCount != 2 {
		t.Fatalf("Refresh() result = %#v", result)
	}
	record := store.snapshot.Interfaces[0]
	if !record.ConfigPresent || !record.RuntimePresent || record.DriftState != "unknown" {
		t.Fatalf("merged interface = %#v", record)
	}
	if len(record.Addresses) != 2 {
		t.Fatalf("addresses = %#v", record.Addresses)
	}
	if len(record.Peers) != 2 {
		t.Fatalf("peers = %#v", record.Peers)
	}
	var foundFile, foundRuntime bool
	for _, peer := range record.Peers {
		switch peer.PublicKey {
		case fileOnlyKey:
			foundFile = peer.Name == "declared" && peer.ActivityState == "unknown"
		case runtimeKey:
			foundRuntime = peer.Name == "named-in-file" && peer.TransferRXBytes == 42
		}
	}
	if !foundFile || !foundRuntime {
		t.Fatalf("merged peers = %#v", record.Peers)
	}
}

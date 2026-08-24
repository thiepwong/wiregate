// File: src/internal/agent/adapters/configfile/source_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package configfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

const (
	fixturePrivateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	fixturePublicKey  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	fixturePSK        = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
)

func TestScanReturnsRedactedInventory(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "test", "fixtures", "wireguard")
	source := New(root, func(string) bool { return true })

	records, issues, err := source.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("Scan() issues = %#v", issues)
	}
	if len(records) != 1 || len(records[0].Peers) != 1 {
		t.Fatalf("Scan() records = %#v", records)
	}
	record := records[0].Interface
	if record.Name != "wg0" || record.Backend != "wg_quick" || !record.ConfigPresent {
		t.Fatalf("unexpected interface = %#v", record)
	}
	if record.Peers[0].PublicKey != fixturePublicKey {
		t.Fatalf("public key = %q", record.Peers[0].PublicKey)
	}
	if got := record.Peers[0].AllowedIPs; len(got) != 2 || got[0] != "10.44.0.2/32" {
		t.Fatalf("allowed IPs = %#v", got)
	}

	serialized := fmt.Sprintf("%#v", records)
	for _, secret := range []string{fixturePrivateKey, fixturePSK} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("redacted inventory retained a secret")
		}
	}
}

func TestScanRejectsZeroPublicKeyAndSymlink(t *testing.T) {
	root := t.TempDir()
	body := []byte("[Interface]\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	if err := os.WriteFile(filepath.Join(root, "wg0.conf"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "wg0.conf"), filepath.Join(root, "wg1.conf")); err != nil {
		t.Fatal(err)
	}
	source := New(root, func(string) bool { return true })

	records, issues, err := source.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(records) != 1 || len(records[0].Peers) != 0 {
		t.Fatalf("unexpected records = %#v", records)
	}
	assertIssue(t, issues, "PEER_PUBLIC_KEY_INVALID")
	assertIssue(t, issues, "CONFIG_SYMLINK_REJECTED")
}

func assertIssue(t *testing.T, issues []inventory.DiagnosticIssue, code string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("issue %q not found in %#v", code, issues)
}

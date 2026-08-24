// File: src/internal/agent/adapters/filesystem/config_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigRejectsTraversalAndSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadConfig("../wg0"); err == nil {
		t.Fatal("path traversal was accepted")
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "wg0.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadConfig("wg0"); err == nil {
		t.Fatal("symlink config was accepted")
	}
}

func TestReadAndCreateConfig(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("[Interface]\n")
	if err := store.CreateConfig("wg0", body, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := store.ReadConfig("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if string(config.Body) != string(body) || config.Hash != SHA256(body) {
		t.Fatalf("config = %#v", config)
	}
	if err := store.CreateConfig("wg0", body, 0o600); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("second create = %v", err)
	}
}

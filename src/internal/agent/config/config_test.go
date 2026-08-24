package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDurationsAndInterfaceAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	body := []byte(`
gateway_id: "01900000-0000-7000-8000-000000000001"
socket_path: "/run/wiregate/agent.sock"
database_path: "/var/lib/wiregate-agent/agent.db"
key_dir: "/etc/wiregate/keys"
wireguard_config_dir: "/etc/wireguard"
allowed_interfaces: ["wg0"]
allowed_peer_uid: 1000
allowed_peer_gid: 1000
runtime_poll_interval: 7s
file_scan_interval: 1m
operation_timeout: 30s
artifact_ttl: 10m
ip_quarantine_duration: 24h
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RuntimePollInterval != 7*time.Second || cfg.FileScanInterval != time.Minute {
		t.Fatalf("durations = %s, %s", cfg.RuntimePollInterval, cfg.FileScanInterval)
	}
	if !cfg.AllowsInterface("wg0") || cfg.AllowsInterface("wg1") || cfg.AllowsInterface("../wg0") {
		t.Fatal("interface allowlist did not fail closed")
	}
}

func TestLoadRejectsUnknownSecuritySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	body := []byte(`
gateway_id: "01900000-0000-7000-8000-000000000001"
allowed_peer_uid: 1000
allowed_peer_gid: 1000
allow_everyone: true
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown agent setting was ignored")
	}
}

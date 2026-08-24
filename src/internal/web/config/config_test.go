// File: src/internal/web/config/config_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublicListenerRequiresTLS(t *testing.T) {
	config := Defaults()
	config.ListenAddress = "0.0.0.0:8443"
	if err := config.Validate(); err == nil {
		t.Fatal("public plaintext listener was accepted")
	}
	config.TLSCertFile = "/etc/wiregate/tls.crt"
	config.TLSKeyFile = "/etc/wiregate/tls.key"
	if err := config.Validate(); err != nil {
		t.Fatalf("public TLS listener rejected: %v", err)
	}
}

func TestLoopbackDevelopmentListenerMayOmitTLS(t *testing.T) {
	config := Defaults()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.ListenAddress = "[::1]:8443"
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsUnknownSecuritySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.yaml")
	if err := os.WriteFile(path, []byte(`
listen_address: "127.0.0.1:8443"
agent_socket: "/run/wiregate/agent.sock"
database_path: "/var/lib/wiregate-web/web.db"
trust_forwarded_headers: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown web setting was ignored")
	}
}

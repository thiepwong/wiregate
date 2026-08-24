// File: src/internal/agent/profile/server_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package profile

import (
	"strings"
	"testing"
)

func TestRenderManagedServerConfig(t *testing.T) {
	body, err := RenderServerConfig(ServerConfig{
		OperationID: "01900000-0000-7000-8000-000000000001",
		PrivateKey:  key(1), Addresses: []string{"10.77.0.1/24"},
		ListenPort: 51820,
		PostUp:     "/usr/sbin/nft -f /etc/wiregate/network/wg0/up.nft",
		PostDown:   "/usr/sbin/nft -f /etc/wiregate/network/wg0/down.nft",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, expected := range []string{
		"# WireGate-Operation:", "Address = 10.77.0.1/24",
		"ListenPort = 51820", "PostUp = /usr/sbin/nft",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("server config missing %q:\n%s", expected, text)
		}
	}
}

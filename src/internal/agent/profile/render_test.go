// File: src/internal/agent/profile/render_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package profile

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func key(value byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)))
}

func TestRenderCanonicalClientConfig(t *testing.T) {
	body, err := RenderClientConfig(ClientConfig{
		PrivateKey: key(1), Addresses: []string{"10.44.0.2/32"},
		DNS: []string{"1.1.1.1"}, MTU: 1420,
		ServerPublicKey: string(key(2)), PresharedKey: key(3),
		EndpointHost: "2001:db8::1", EndpointPort: 51820,
		Routes: []string{"10.0.0.0/8"}, PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := `[Interface]
PrivateKey = ` + string(key(1)) + `
Address = 10.44.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ` + string(key(2)) + `
PresharedKey = ` + string(key(3)) + `
Endpoint = [2001:db8::1]:51820
AllowedIPs = 10.0.0.0/8
PersistentKeepalive = 25
`
	if string(body) != expected {
		t.Fatalf("config mismatch:\n%s", body)
	}
}

func TestRenderDoesNotConfuseServerAllowedIPsWithClientRoutes(t *testing.T) {
	body, err := RenderClientConfig(ClientConfig{
		PrivateKey: key(1), Addresses: []string{"10.44.0.2/32"},
		ServerPublicKey: string(key(2)),
		EndpointHost:    "vpn.example.com", EndpointPort: 51820,
		Routes: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "AllowedIPs = 10.44.0.2/32") {
		t.Fatal("client address leaked into client routes")
	}
}

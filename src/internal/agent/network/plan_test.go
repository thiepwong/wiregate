// File: src/internal/agent/network/plan_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package network

import (
	"strings"
	"testing"
)

func TestManagedFullTunnelPlanOwnsOneTable(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		InterfaceID:   "01900000-0000-7000-8000-000000000001",
		InterfaceName: "wg0", Profile: ProfileFullTunnel,
		FirewallMode: FirewallManagedNFT, ListenPort: 51820,
		TunnelCIDRs: []string{"10.44.0.0/24"}, EgressDevice: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	up := string(plan.UpNFT)
	if !strings.Contains(up, "table inet wiregate_019000000000") ||
		!strings.Contains(up, `ip saddr 10.44.0.0/24 oifname "eth0" masquerade`) {
		t.Fatalf("up.nft:\n%s", up)
	}
	if strings.Contains(up, "policy drop") {
		t.Fatal("generated owned base chain uses policy drop")
	}
	if string(plan.DownNFT) != "destroy table inet wiregate_019000000000\n" {
		t.Fatalf("down.nft = %q", plan.DownNFT)
	}
}

func TestExternalModeDoesNotGenerateFirewallMutation(t *testing.T) {
	plan, err := BuildPlan(PlanInput{
		InterfaceID:   "01900000-0000-7000-8000-000000000001",
		InterfaceName: "wg0", Profile: ProfileLAN,
		FirewallMode: FirewallExternal, ListenPort: 51820,
		TunnelCIDRs: []string{"10.44.0.0/24"},
		LANCIDRs:    []string{"10.0.0.0/8"}, EgressDevice: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UpNFT) != 0 || len(plan.DownNFT) != 0 || len(plan.ExternalChecklist) == 0 {
		t.Fatalf("external plan = %#v", plan)
	}
}

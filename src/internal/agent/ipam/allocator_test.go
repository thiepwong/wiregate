// File: src/internal/agent/ipam/allocator_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package ipam

import (
	"net/netip"
	"testing"
)

func TestAllocateSkipsNetworkGatewayAllocatedAndQuarantine(t *testing.T) {
	result, err := Allocate(CandidateSet{
		Pool:    netip.MustParsePrefix("10.0.0.0/29"),
		Gateway: netip.MustParseAddr("10.0.0.1"),
		Allocated: map[netip.Addr]struct{}{
			netip.MustParseAddr("10.0.0.2"): {},
		},
		Quarantined: map[netip.Addr]struct{}{
			netip.MustParseAddr("10.0.0.3"): {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.String() != "10.0.0.4" {
		t.Fatalf("allocated %s", result)
	}
}

func TestValidatePoolRejectsOverlap(t *testing.T) {
	err := ValidatePool(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParseAddr("10.0.0.1"),
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.128/25")},
	)
	if err == nil {
		t.Fatal("overlapping pool was accepted")
	}
}

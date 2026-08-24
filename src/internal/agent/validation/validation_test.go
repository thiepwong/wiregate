package validation

import (
	"net/netip"
	"testing"
)

func TestRejectOverlappingAllowedIPs(t *testing.T) {
	candidate, err := CanonicalPrefixes([]string{"10.0.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectOverlaps(candidate, []OwnedPrefix{{
		PeerID: "peer-1", Prefix: netip.MustParsePrefix("10.0.0.0/24"),
	}}, ""); err == nil {
		t.Fatal("overlap was accepted")
	}
	if err := RejectOverlaps(candidate, []OwnedPrefix{{
		PeerID: "peer-1", Prefix: netip.MustParsePrefix("10.0.0.0/24"),
	}}, "peer-1"); err != nil {
		t.Fatalf("excluded peer conflicted: %v", err)
	}
}

func TestTunnelAddressRequiresHostPrefix(t *testing.T) {
	if _, err := TunnelAddress("10.0.0.2/24"); err == nil {
		t.Fatal("IPv4 network was accepted as a peer tunnel address")
	}
	if _, err := TunnelAddress("fd00::2/128"); err != nil {
		t.Fatal(err)
	}
}

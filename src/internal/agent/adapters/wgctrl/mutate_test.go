package wgctrl

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestBuildPeerConfigIsTargeted(t *testing.T) {
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	config, err := BuildPeerConfig(PeerSpec{
		PublicKey: public, PresharedKey: []byte(psk),
		AllowedIPs: []string{"10.0.0.2/32"}, PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.PublicKey.String() != public || config.Remove ||
		!config.ReplaceAllowedIPs || len(config.AllowedIPs) != 1 ||
		config.PersistentKeepaliveInterval == nil {
		t.Fatalf("peer config = %#v", config)
	}
}

func TestBuildRemovePeerOnlyMarksTarget(t *testing.T) {
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	config, err := BuildRemovePeer(public)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Remove || config.PublicKey.String() != public {
		t.Fatalf("remove config = %#v", config)
	}
}

package control

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCanonicalPresharedKeyAcceptsCurrentAndLegacyAdoptionPayloads(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	want := base64.StdEncoding.EncodeToString(raw)
	legacy, err := canonicalPresharedKey(bytes.Clone(raw))
	if err != nil || string(legacy) != want {
		t.Fatalf("legacy PSK = %q, err = %v", legacy, err)
	}
	clear(legacy)
	current, err := canonicalPresharedKey([]byte(want))
	if err != nil || string(current) != want {
		t.Fatalf("current PSK = %q, err = %v", current, err)
	}
	clear(current)
	if _, err := canonicalPresharedKey([]byte("invalid")); err == nil {
		t.Fatal("invalid PSK envelope was accepted")
	}
}

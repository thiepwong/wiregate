package configdoc

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func TestNoOpIsByteIdentical(t *testing.T) {
	raw := []byte("# heading\r\n[Interface]\r\nPrivateKey  = " + testKey(1) + " \r\nX-Future = retained\r\n\r\n[Peer]\r\n# label\r\nPublicKey = " + testKey(2) + "\r\nAllowedIPs = 10.0.0.2/32\r\n")
	document, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(document.Bytes(), raw) {
		t.Fatalf("no-op changed bytes:\n%q\n%q", raw, document.Bytes())
	}
	analysis := document.Analysis()
	if analysis.InterfaceCount != 1 || len(analysis.Peers) != 1 {
		t.Fatalf("analysis = %#v", analysis)
	}
	if err := document.AdoptionSafe(); err != nil {
		t.Fatalf("unknown keys must be preserved as warnings, not block a safe peer patch: %v", err)
	}
}

func TestPatchTouchesOnlyTargetPeer(t *testing.T) {
	first := testKey(2)
	second := testKey(3)
	raw := []byte("[Interface]\nPrivateKey = " + testKey(1) + "\n\n[Peer]\nPublicKey = " + first + "\nAllowedIPs  = 10.0.0.2/32  \nX-Peer = keep\n\n[Peer]\nPublicKey = " + second + "\nAllowedIPs = 10.0.0.3/32\n")
	document, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	beforeSecond := raw[bytes.Index(raw, []byte("[Peer]\nPublicKey = "+second)):]
	allowed := []string{"10.0.0.20/32", "fd00::20/128"}
	if err := document.PatchPeer(first, PeerPatch{AllowedIPs: &allowed}); err != nil {
		t.Fatal(err)
	}
	got := document.Bytes()
	if !bytes.Contains(got, []byte("AllowedIPs  = 10.0.0.20/32, fd00::20/128  \n")) {
		t.Fatalf("target whitespace was not preserved:\n%s", got)
	}
	afterSecond := got[bytes.Index(got, []byte("[Peer]\nPublicKey = "+second)):]
	if !bytes.Equal(afterSecond, beforeSecond) {
		t.Fatalf("non-target peer changed:\n%s\n%s", beforeSecond, afterSecond)
	}
}

func TestRemoveReturnsExactBlockAndAddPreservesDocument(t *testing.T) {
	key := testKey(4)
	raw := []byte("[Interface]\nPrivateKey = " + testKey(1) + "\n\n[Peer]\n# exact comment\nPublicKey = " + key + "\nAllowedIPs = 10.0.0.4/32\n")
	document, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := document.RemovePeer(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(archived) != "[Peer]\n# exact comment\nPublicKey = "+key+"\nAllowedIPs = 10.0.0.4/32\n" {
		t.Fatalf("archived block = %q", archived)
	}
	if strings.Contains(string(document.Bytes()), key) {
		t.Fatal("removed peer remains in document")
	}
	if err := document.AddPeer(NewPeer{
		PublicKey: key, AllowedIPs: []string{"10.0.0.4/32"},
		PersistentKeepalive: 25,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document.Bytes()), "PersistentKeepalive = 25") {
		t.Fatalf("added document:\n%s", document.Bytes())
	}
}

func TestRestorePeerBlockPreservesExactArchivedBytes(t *testing.T) {
	key := testKey(5)
	block := []byte("[Peer]\n# retained label\nPublicKey  = " + key + "  \nEndpoint = vpn.example:51820\nAllowedIPs = 10.0.0.5/32\n")
	raw := append([]byte("[Interface]\nPrivateKey = "+testKey(1)+"\n\n"), block...)
	document, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := document.RemovePeer(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(archived, block) {
		t.Fatalf("archived block changed:\n%q\n%q", block, archived)
	}
	if err := document.RestorePeerBlock(key, archived); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document.Bytes(), block) {
		t.Fatalf("restored block changed:\n%s", document.Bytes())
	}
}

func TestAdoptionRejectsUnsafeSyntaxAndSaveConfigIsDetected(t *testing.T) {
	raw := []byte("[Interface]\nSaveConfig = true\nraw shell-like text\n")
	document, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !document.Analysis().SaveConfig {
		t.Fatal("SaveConfig was not detected")
	}
	if err := document.AdoptionSafe(); err == nil {
		t.Fatal("unsafe raw statement was accepted")
	}
}

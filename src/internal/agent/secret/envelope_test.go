package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvelopeRoundTripAADAndRewrap(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	context := Context{
		GatewayID: "01900000-0000-7000-8000-000000000001",
		OwnerType: "peer", OwnerID: "peer-1", Purpose: "preshared_key",
	}
	plaintext := []byte("sensitive")
	envelope, err := Seal(oldKey, 1, context, plaintext, []byte("fingerprint"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(oldKey, context, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext = %q", opened)
	}
	wrong := context
	wrong.OwnerID = "peer-2"
	if _, err := Open(oldKey, wrong, envelope); err == nil {
		t.Fatal("AAD owner substitution was accepted")
	}

	rewrapped, err := Rewrap(oldKey, newKey, 2, context, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewrapped.Ciphertext, envelope.Ciphertext) ||
		!bytes.Equal(rewrapped.PayloadNonce, envelope.PayloadNonce) {
		t.Fatal("rewrap modified payload encryption")
	}
	if _, err := Open(oldKey, context, rewrapped); err == nil {
		t.Fatal("old key opened rewrapped envelope")
	}
	opened, err = Open(newKey, context, rewrapped)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open rewrapped = %q, %v", opened, err)
	}
}

func TestEnvelopeTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	context := Context{GatewayID: "gateway", OwnerType: "peer", OwnerID: "1", Purpose: "client_private_key"}
	envelope, err := Seal(key, 1, context, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := Open(key, context, envelope); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func TestKeyStoreModesAndSymlinkRejection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "keys")
	store, err := NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateMaster(1)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadMaster(1)
	if err != nil || !bytes.Equal(created, loaded) {
		t.Fatalf("loaded key mismatch: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "key-v0001.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	if err := os.Symlink(filepath.Join(root, "key-v0001.bin"), filepath.Join(root, "fingerprint.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadFingerprint(); err == nil {
		t.Fatal("symlink key was accepted")
	}
}

func TestKeyStoreInitializeCreatesIndependentKeysOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "keys")
	store, err := NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	master, fingerprint, err := store.Initialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(master) != 32 || len(fingerprint) != 32 || bytes.Equal(master, fingerprint) {
		t.Fatal("initializer did not create two independent 32-byte keys")
	}
	if _, _, err := store.Initialize(); err == nil {
		t.Fatal("second initialization overwrote key material")
	}
}

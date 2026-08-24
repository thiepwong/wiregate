// Package secret owns WireGate secret encryption. It intentionally exposes
// byte slices rather than string formatting helpers so secret values are not
// accidentally included in logs.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	Algorithm  = "xchacha20-poly1305+hkdf-sha256"
	AADVersion = 1
	keySize    = chacha20poly1305.KeySize
)

type Context struct {
	GatewayID string
	OwnerType string
	OwnerID   string
	Purpose   string
}

type Envelope struct {
	Algorithm         string
	Ciphertext        []byte
	PayloadNonce      []byte
	WrappedDEK        []byte
	WrapNonce         []byte
	KeyVersion        uint32
	AADVersion        uint32
	SecretFingerprint []byte
}

func Seal(masterKey []byte, keyVersion uint32, context Context, plaintext, fingerprint []byte) (Envelope, error) {
	if err := validateInputs(masterKey, keyVersion, context); err != nil {
		return Envelope{}, err
	}
	dek := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Envelope{}, fmt.Errorf("generate data encryption key: %w", err)
	}
	defer wipe(dek)

	payloadAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("create payload cipher: %w", err)
	}
	payloadNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, payloadNonce); err != nil {
		return Envelope{}, fmt.Errorf("generate payload nonce: %w", err)
	}
	// Payload AAD is intentionally independent of the KEK version. The key
	// version authenticates the wrapped DEK; keeping it out of payload AAD is
	// what permits a KEK rotation to re-wrap only the DEK.
	aad := encodeAAD(context, 0, "payload")
	ciphertext := payloadAEAD.Seal(nil, payloadNonce, plaintext, aad)

	wrapKey, err := deriveWrapKey(masterKey, context.GatewayID)
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(wrapKey)
	wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("create wrapping cipher: %w", err)
	}
	wrapNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return Envelope{}, fmt.Errorf("generate wrapping nonce: %w", err)
	}
	wrappedDEK := wrapAEAD.Seal(nil, wrapNonce, dek, encodeAAD(context, keyVersion, "wrap"))

	return Envelope{
		Algorithm:         Algorithm,
		Ciphertext:        ciphertext,
		PayloadNonce:      payloadNonce,
		WrappedDEK:        wrappedDEK,
		WrapNonce:         wrapNonce,
		KeyVersion:        keyVersion,
		AADVersion:        AADVersion,
		SecretFingerprint: append([]byte(nil), fingerprint...),
	}, nil
}

func Open(masterKey []byte, context Context, envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(masterKey, context, envelope); err != nil {
		return nil, err
	}
	dek, err := unwrapDEK(masterKey, context, envelope)
	if err != nil {
		return nil, err
	}
	defer wipe(dek)
	payloadAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("create payload cipher: %w", err)
	}
	plaintext, err := payloadAEAD.Open(
		nil,
		envelope.PayloadNonce,
		envelope.Ciphertext,
		encodeAAD(context, 0, "payload"),
	)
	if err != nil {
		return nil, errors.New("decrypt secret payload: authentication failed")
	}
	return plaintext, nil
}

// Rewrap changes only the encrypted DEK. The payload ciphertext and payload
// nonce remain byte-identical, which is the key-rotation contract in the DAD.
func Rewrap(oldMasterKey, newMasterKey []byte, newKeyVersion uint32, context Context, envelope Envelope) (Envelope, error) {
	if newKeyVersion == 0 {
		return Envelope{}, errors.New("new key version must be positive")
	}
	if len(newMasterKey) != keySize {
		return Envelope{}, fmt.Errorf("new master key must be %d bytes", keySize)
	}
	if err := validateEnvelope(oldMasterKey, context, envelope); err != nil {
		return Envelope{}, err
	}
	dek, err := unwrapDEK(oldMasterKey, context, envelope)
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(dek)

	wrapKey, err := deriveWrapKey(newMasterKey, context.GatewayID)
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(wrapKey)
	wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("create wrapping cipher: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate wrapping nonce: %w", err)
	}
	result := cloneEnvelope(envelope)
	result.WrappedDEK = wrapAEAD.Seal(nil, nonce, dek, encodeAAD(context, newKeyVersion, "wrap"))
	result.WrapNonce = nonce
	result.KeyVersion = newKeyVersion
	return result, nil
}

func Fingerprint(key, secret []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("fingerprint key must be %d bytes", keySize)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(secret)
	return mac.Sum(nil), nil
}

func TokenHash(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

func validateInputs(masterKey []byte, keyVersion uint32, context Context) error {
	if len(masterKey) != keySize {
		return fmt.Errorf("master key must be %d bytes", keySize)
	}
	if keyVersion == 0 {
		return errors.New("key version must be positive")
	}
	if context.GatewayID == "" || context.OwnerType == "" || context.OwnerID == "" || context.Purpose == "" {
		return errors.New("all secret AAD context fields are required")
	}
	return nil
}

func validateEnvelope(masterKey []byte, context Context, envelope Envelope) error {
	if err := validateInputs(masterKey, envelope.KeyVersion, context); err != nil {
		return err
	}
	switch {
	case envelope.Algorithm != Algorithm:
		return fmt.Errorf("unsupported secret algorithm %q", envelope.Algorithm)
	case envelope.AADVersion != AADVersion:
		return fmt.Errorf("unsupported AAD version %d", envelope.AADVersion)
	case len(envelope.PayloadNonce) != chacha20poly1305.NonceSizeX:
		return errors.New("invalid payload nonce length")
	case len(envelope.WrapNonce) != chacha20poly1305.NonceSizeX:
		return errors.New("invalid wrap nonce length")
	case len(envelope.WrappedDEK) != keySize+chacha20poly1305.Overhead:
		return errors.New("invalid wrapped key length")
	}
	return nil
}

func unwrapDEK(masterKey []byte, context Context, envelope Envelope) ([]byte, error) {
	wrapKey, err := deriveWrapKey(masterKey, context.GatewayID)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapKey)
	wrapAEAD, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("create wrapping cipher: %w", err)
	}
	dek, err := wrapAEAD.Open(
		nil,
		envelope.WrapNonce,
		envelope.WrappedDEK,
		encodeAAD(context, envelope.KeyVersion, "wrap"),
	)
	if err != nil {
		return nil, errors.New("decrypt wrapped key: authentication failed")
	}
	return dek, nil
}

func deriveWrapKey(masterKey []byte, gatewayID string) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, []byte(gatewayID), []byte("wiregate/wrap/v1"))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive wrapping key: %w", err)
	}
	return key, nil
}

func encodeAAD(context Context, keyVersion uint32, domain string) []byte {
	var result []byte
	for _, value := range []string{
		"wiregate/secret/v1",
		domain,
		context.GatewayID,
		context.OwnerType,
		context.OwnerID,
		context.Purpose,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		result = append(result, length[:]...)
		result = append(result, value...)
	}
	var number [4]byte
	binary.BigEndian.PutUint32(number[:], AADVersion)
	result = append(result, number[:]...)
	binary.BigEndian.PutUint32(number[:], keyVersion)
	result = append(result, number[:]...)
	return result
}

func cloneEnvelope(source Envelope) Envelope {
	result := source
	result.Ciphertext = append([]byte(nil), source.Ciphertext...)
	result.PayloadNonce = append([]byte(nil), source.PayloadNonce...)
	result.WrappedDEK = append([]byte(nil), source.WrappedDEK...)
	result.WrapNonce = append([]byte(nil), source.WrapNonce...)
	result.SecretFingerprint = append([]byte(nil), source.SecretFingerprint...)
	return result
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

package control

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	"github.com/wiregate-project/wiregate/internal/agent/profile"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

// ExportClientConfig decrypts managed client material only for the duration of
// rendering. External and one-time profiles deliberately cannot be recreated.
func (s *Service) ExportClientConfig(ctx context.Context, peerID string, actor Actor) ([]byte, string, error) {
	if err := validateActor(actor, "client:export-secret", false); err != nil {
		return nil, "", err
	}
	material, err := s.repository.ClientMaterial(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if material.KeyMode != "managed" || material.ProfileState != "ready" || material.ClientPrivate == nil {
		return nil, "", fmt.Errorf("%w: client material is not re-exportable", ErrPrecondition)
	}
	privateKey, err := s.openPeerSecret(material.ClientPrivate)
	if err != nil {
		return nil, "", err
	}
	defer wipe(privateKey)
	var presharedKey []byte
	if material.PresharedKey != nil {
		presharedKey, err = s.openPeerSecret(material.PresharedKey)
		if err != nil {
			return nil, "", err
		}
		defer wipe(presharedKey)
	}
	serverPublicKey := material.ServerPublicKey
	if serverPublicKey == "" {
		device, inspectErr := host.InspectDevice(material.InterfaceName)
		if inspectErr != nil {
			return nil, "", inspectErr
		}
		serverPublicKey = device.PublicKey
	}
	var dns []string
	if material.DNSJSON != "" {
		if err := json.Unmarshal([]byte(material.DNSJSON), &dns); err != nil {
			return nil, "", err
		}
	}
	body, err := profile.RenderClientConfig(profile.ClientConfig{
		PrivateKey: privateKey, Addresses: material.Addresses, DNS: dns,
		MTU: uint16(material.MTU), ServerPublicKey: serverPublicKey,
		PresharedKey: presharedKey, EndpointHost: material.EndpointHost,
		EndpointPort: uint16(material.EndpointPort), Routes: material.Routes,
		PersistentKeepalive: uint16(material.PersistentKeepalive),
	})
	if err != nil {
		return nil, "", err
	}
	return body, safeArtifactName(material.PeerName), nil
}

func (s *Service) openPeerSecret(input *repository.SecretInput) ([]byte, error) {
	master, err := s.masterKey(input.Envelope.KeyVersion)
	if err != nil {
		return nil, err
	}
	defer wipe(master)
	payload, err := secret.Open(master, input.Context, input.Envelope)
	if err != nil || input.Context.Purpose != "preshared_key" {
		return payload, err
	}
	return canonicalPresharedKey(payload)
}

func canonicalPresharedKey(payload []byte) ([]byte, error) {
	decoded, decodeErr := base64.StdEncoding.DecodeString(string(payload))
	if decodeErr == nil && len(decoded) == 32 {
		clear(decoded)
		return payload, nil
	}
	clear(decoded)
	// Adoption builds before schema v4 encrypted the canonical 32-byte PSK
	// directly. Normalize those envelopes at the privileged boundary so an
	// upgraded installation can enable an already-adopted peer safely.
	if len(payload) == 32 {
		canonical := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
		base64.StdEncoding.Encode(canonical, payload)
		wipe(payload)
		return canonical, nil
	}
	wipe(payload)
	return nil, errors.New("preshared key envelope has an invalid canonical form")
}

func safeArtifactName(value string) string {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			result = append(result, character)
		} else if len(result) == 0 || result[len(result)-1] != '-' {
			result = append(result, '-')
		}
	}
	if len(result) == 0 {
		return "wireguard-client"
	}
	return string(result)
}

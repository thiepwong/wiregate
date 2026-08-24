package wgctrl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerSpec struct {
	PublicKey           string
	PresharedKey        []byte
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive uint16
}

// BuildPeerConfig always describes one target peer. Callers pass the returned
// value in a device config with ReplacePeers=false, preserving every unrelated
// peer and avoiding interface down/up.
func BuildPeerConfig(spec PeerSpec) (wgtypes.PeerConfig, error) {
	publicKey, err := wgtypes.ParseKey(strings.TrimSpace(spec.PublicKey))
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parse peer public key: %w", err)
	}
	config := wgtypes.PeerConfig{
		PublicKey: publicKey,
	}
	if len(spec.PresharedKey) > 0 {
		value := strings.TrimSpace(string(spec.PresharedKey))
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return wgtypes.PeerConfig{}, errors.New("preshared key must be a 32-byte base64 value")
		}
		var key wgtypes.Key
		copy(key[:], decoded)
		clear(decoded)
		config.PresharedKey = &key
	}
	for _, value := range spec.AllowedIPs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parse AllowedIPs %q: %w", value, err)
		}
		prefix = prefix.Masked()
		config.AllowedIPs = append(config.AllowedIPs, net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		})
	}
	if len(config.AllowedIPs) == 0 {
		return wgtypes.PeerConfig{}, errors.New("peer requires at least one AllowedIPs prefix")
	}
	replaceAllowed := true
	config.ReplaceAllowedIPs = replaceAllowed
	if spec.Endpoint != "" {
		endpoint, err := net.ResolveUDPAddr("udp", spec.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolve peer endpoint: %w", err)
		}
		config.Endpoint = endpoint
	}
	keepalive := time.Duration(spec.PersistentKeepalive) * time.Second
	config.PersistentKeepaliveInterval = &keepalive
	return config, nil
}

func BuildRemovePeer(publicKey string) (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(strings.TrimSpace(publicKey))
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parse peer public key: %w", err)
	}
	return wgtypes.PeerConfig{PublicKey: key, Remove: true}, nil
}

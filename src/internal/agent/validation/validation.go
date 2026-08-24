// File: src/internal/agent/validation/validation.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package validation

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)

func InterfaceName(name string) error {
	if !interfaceNamePattern.MatchString(name) {
		return errors.New("interface name must match ^[A-Za-z0-9_=+.-]{1,15}$")
	}
	return nil
}

func WireGuardKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return errors.New("WireGuard key must decode to exactly 32 bytes")
	}
	var nonzero byte
	for _, item := range decoded {
		nonzero |= item
	}
	if nonzero == 0 {
		return errors.New("WireGuard public key cannot be all zero")
	}
	return nil
}

func ListenPort(port uint16) error {
	if port == 0 {
		return errors.New("listen port must be between 1 and 65535")
	}
	return nil
}

func PersistentKeepalive(seconds uint16) error {
	// uint16 already guarantees the upper bound. Zero explicitly means omit.
	return nil
}

func CanonicalPrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", value)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Addr().BitLen() != result[j].Addr().BitLen() {
			return result[i].Addr().BitLen() < result[j].Addr().BitLen()
		}
		if result[i].Addr() != result[j].Addr() {
			return result[i].Addr().Less(result[j].Addr())
		}
		return result[i].Bits() < result[j].Bits()
	})
	return result, nil
}

func TunnelAddress(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid tunnel address: %w", err)
	}
	switch {
	case prefix.Addr().Is4() && prefix.Bits() != 32:
		return netip.Prefix{}, errors.New("IPv4 peer tunnel address must be /32")
	case prefix.Addr().Is6() && prefix.Bits() != 128:
		return netip.Prefix{}, errors.New("IPv6 peer tunnel address must be /128")
	}
	return prefix, nil
}

type OwnedPrefix struct {
	PeerID string
	Prefix netip.Prefix
}

func RejectOverlaps(candidate []netip.Prefix, existing []OwnedPrefix, excludedPeerID string) error {
	for _, proposed := range candidate {
		for _, current := range existing {
			if current.PeerID == excludedPeerID {
				continue
			}
			if proposed.Addr().BitLen() != current.Prefix.Addr().BitLen() {
				continue
			}
			if proposed.Overlaps(current.Prefix) {
				return fmt.Errorf(
					"AllowedIPs %s overlaps %s owned by peer %s",
					proposed, current.Prefix, current.PeerID,
				)
			}
		}
	}
	return nil
}

func EndpointHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("endpoint host is required")
	}
	if strings.ContainsAny(host, "\r\n\t /") {
		return errors.New("endpoint host contains invalid characters")
	}
	trimmed := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if net.ParseIP(trimmed) != nil {
		return nil
	}
	if len(host) > 253 {
		return errors.New("endpoint DNS name is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("endpoint DNS name has an invalid label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("endpoint DNS label cannot start or end with a hyphen")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') &&
				character != '-' {
				return errors.New("endpoint DNS name contains an invalid character")
			}
		}
	}
	return nil
}

func MTU(value uint16) error {
	if value != 0 && (value < 1280 || value > 9000) {
		return errors.New("MTU must be zero (omit) or between 1280 and 9000")
	}
	return nil
}

func DNS(values []string) error {
	for _, value := range values {
		if _, err := netip.ParseAddr(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("DNS value %q must be an IP literal", value)
		}
	}
	return nil
}

//go:build linux

// File: src/internal/agent/adapters/wgctrl/source_linux.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package wgctrl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Source struct{}

func New() *Source {
	return &Source{}
}

func (s *Source) List(ctx context.Context) ([]inventory.RuntimeRecord, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()

	devices, err := client.Devices()
	if err != nil {
		return nil, fmt.Errorf("list WireGuard devices: %w", err)
	}
	now := time.Now().UTC()
	records := make([]inventory.RuntimeRecord, 0, len(devices))
	for _, device := range devices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record := inventory.Interface{
			Name:               device.Name,
			Backend:            "runtime_only",
			ManagementMode:     "observed",
			RuntimePresent:     true,
			RuntimeFingerprint: RuntimeFingerprint(device),
			DriftState:         "none",
		}
		for _, runtimePeer := range device.Peers {
			allowed := make([]string, 0, len(runtimePeer.AllowedIPs))
			for _, prefix := range runtimePeer.AllowedIPs {
				allowed = append(allowed, prefix.String())
			}
			sort.Strings(allowed)
			endpoint := ""
			if runtimePeer.Endpoint != nil {
				endpoint = runtimePeer.Endpoint.String()
			}
			record.Peers = append(record.Peers, inventory.Peer{
				Name:                shortKey(runtimePeer.PublicKey.String()),
				PublicKey:           runtimePeer.PublicKey.String(),
				Endpoint:            endpoint,
				PersistentKeepalive: int(runtimePeer.PersistentKeepaliveInterval.Seconds()),
				AllowedIPs:          allowed,
				LatestHandshakeAt:   runtimePeer.LastHandshakeTime.UTC(),
				TransferRXBytes:     uint64(max(runtimePeer.ReceiveBytes, 0)),
				TransferTXBytes:     uint64(max(runtimePeer.TransmitBytes, 0)),
				RuntimeSeenAt:       now,
				ActivityState:       activity(runtimePeer.LastHandshakeTime, now),
			})
		}
		records = append(records, inventory.RuntimeRecord{Interface: record})
	}
	return records, nil
}

func RuntimeFingerprint(device *wgtypes.Device) string {
	parts := []string{
		device.Name,
		device.PublicKey.String(),
		fmt.Sprintf("%d", device.ListenPort),
		fmt.Sprintf("%d", device.FirewallMark),
	}
	peers := make([]string, 0, len(device.Peers))
	for _, peer := range device.Peers {
		allowed := make([]string, 0, len(peer.AllowedIPs))
		for _, prefix := range peer.AllowedIPs {
			allowed = append(allowed, prefix.String())
		}
		sort.Strings(allowed)
		peers = append(peers, strings.Join([]string{
			peer.PublicKey.String(),
			strings.Join(allowed, ","),
			peer.PersistentKeepaliveInterval.String(),
		}, "\x1f"))
	}
	sort.Strings(peers)
	parts = append(parts, peers...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func activity(handshake, now time.Time) string {
	if handshake.IsZero() {
		return "never_seen"
	}
	if now.Sub(handshake) <= 3*time.Minute {
		return "active"
	}
	return "idle"
}

func shortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return "external-" + key[:8]
}

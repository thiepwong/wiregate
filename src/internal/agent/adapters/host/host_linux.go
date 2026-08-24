//go:build linux

// File: src/internal/agent/adapters/host/host_linux.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	wgadapter "github.com/wiregate-project/wiregate/internal/agent/adapters/wgctrl"
	"github.com/wiregate-project/wiregate/internal/agent/validation"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type DeviceState struct {
	Present           bool
	PublicKey         string
	ListenPort        int
	Fingerprint       string
	LegacyFingerprint string
}

type PeerState struct {
	Present    bool
	AllowedIPs []string
}

func RequireNativeTools(requireNFT bool) error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("native systemd agent is required")
	}
	for _, name := range []string{"wg", "wg-quick", "systemctl"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required host tool %s is unavailable", name)
		}
	}
	if requireNFT {
		if _, err := exec.LookPath("nft"); err != nil {
			return errors.New("nftables tool is unavailable")
		}
	}
	return nil
}

func LockInterface(name string) (func() error, error) {
	if err := validation.InterfaceName(name); err != nil {
		return nil, err
	}
	if err := os.MkdirAll("/run/wiregate/locks", 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join("/run/wiregate/locks", name+".lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() error {
		unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return errors.Join(unlockErr, file.Close())
	}, nil
}

func ManagedNFTConflict(ctx context.Context) (string, error) {
	command := exec.CommandContext(ctx, "nft", "list", "ruleset")
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("inspect nftables ruleset: %s", bounded(output))
	}
	text := strings.ToLower(string(output))
	if strings.Contains(text, "chain docker-user") &&
		strings.Contains(text, "chain forward") && strings.Contains(text, "policy drop") {
		return "Docker owns a FORWARD drop path; use external firewall mode and apply the generated checklist.", nil
	}
	if strings.Contains(text, "table inet firewalld") || strings.Contains(text, "table inet ufw") {
		return "An external firewall manager owns active nftables objects; use external firewall mode.", nil
	}
	return "", nil
}

func InterfaceExists(name string) (bool, error) {
	if err := validation.InterfaceName(name); err != nil {
		return false, err
	}
	_, err := netlink.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &notFound):
		return false, nil
	default:
		return false, err
	}
}

func OccupiedPrefixes() ([]netip.Prefix, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host links: %w", err)
	}
	seen := make(map[netip.Prefix]struct{})
	for _, link := range links {
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("list host addresses: %w", err)
		}
		for _, address := range addresses {
			if address.IPNet == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(address.IPNet.String())
			if err == nil && prefix.Bits() != 0 {
				seen[prefix.Masked()] = struct{}{}
			}
		}
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list host routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Dst.String())
		if err == nil && prefix.Bits() != 0 {
			seen[prefix.Masked()] = struct{}{}
		}
	}
	result := make([]netip.Prefix, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix)
	}
	return result, nil
}

func UDPPortAvailable(port uint16) error {
	if err := validation.ListenPort(port); err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err == nil {
		devices, listErr := client.Devices()
		_ = client.Close()
		if listErr == nil {
			for _, device := range devices {
				if device.ListenPort == int(port) {
					return fmt.Errorf("UDP port %d is already used by WireGuard interface %s", port, device.Name)
				}
			}
		}
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
	if err != nil {
		return fmt.Errorf("UDP port %d is unavailable: %w", port, err)
	}
	return listener.Close()
}

func WriteOwnedFile(path string, body []byte, mode fs.FileMode, directoryMode fs.FileMode) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("owned file path must be absolute")
	}
	parent := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(parent, directoryMode); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("owned file parent must be a real directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return err
	}
	remove = false
	return nil
}

func RemoveOwnedFile(path, marker string) error {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if marker == "" || !bytes.Contains(body, []byte(marker)) {
		return errors.New("refusing to remove file without matching ownership marker")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ValidateNFT(ctx context.Context, path string) error {
	command := exec.CommandContext(ctx, "nft", "--check", "--file", path)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables validation failed: %s", bounded(output))
	}
	return nil
}

func ApplyNFT(ctx context.Context, path string) error {
	command := exec.CommandContext(ctx, "nft", "--file", path)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables apply failed: %s", bounded(output))
	}
	return nil
}

func StartService(ctx context.Context, interfaceName string) error {
	return systemctl(ctx, "start", unit(interfaceName))
}

func StopService(ctx context.Context, interfaceName string) error {
	return systemctl(ctx, "stop", unit(interfaceName))
}

func EnableService(ctx context.Context, interfaceName string) error {
	return systemctl(ctx, "enable", unit(interfaceName))
}

func DisableService(ctx context.Context, interfaceName string) error {
	return systemctl(ctx, "disable", unit(interfaceName))
}

func ServiceActive(ctx context.Context, interfaceName string) bool {
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit(interfaceName)).Run() == nil
}

func ServiceEnabled(ctx context.Context, interfaceName string) bool {
	return exec.CommandContext(ctx, "systemctl", "is-enabled", "--quiet", unit(interfaceName)).Run() == nil
}

func systemctl(ctx context.Context, action, service string) error {
	command := exec.CommandContext(ctx, "systemctl", action, service)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd %s failed: %s", action, bounded(output))
	}
	return nil
}

func unit(interfaceName string) string {
	if validation.InterfaceName(interfaceName) != nil {
		return "wg-quick@invalid.service"
	}
	return "wg-quick@" + interfaceName + ".service"
}

func InspectDevice(interfaceName string) (DeviceState, error) {
	if err := validation.InterfaceName(interfaceName); err != nil {
		return DeviceState{}, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return DeviceState{}, err
	}
	defer client.Close()
	device, err := client.Device(interfaceName)
	if err != nil {
		return DeviceState{}, nil
	}
	legacyValue := strings.Join([]string{device.Name, device.PublicKey.String(), fmt.Sprint(device.ListenPort)}, "\x00")
	legacySum := sha256.Sum256([]byte(legacyValue))
	return DeviceState{
		Present: true, PublicKey: device.PublicKey.String(), ListenPort: device.ListenPort,
		Fingerprint: wgadapter.RuntimeFingerprint(device), LegacyFingerprint: hex.EncodeToString(legacySum[:]),
	}, nil
}

func InspectPeer(interfaceName, publicKey string) (PeerState, error) {
	if err := validation.InterfaceName(interfaceName); err != nil {
		return PeerState{}, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return PeerState{}, err
	}
	defer client.Close()
	device, err := client.Device(interfaceName)
	if err != nil {
		return PeerState{}, err
	}
	for _, peer := range device.Peers {
		if peer.PublicKey.String() != strings.TrimSpace(publicKey) {
			continue
		}
		state := PeerState{Present: true}
		for _, prefix := range peer.AllowedIPs {
			state.AllowedIPs = append(state.AllowedIPs, prefix.String())
		}
		return state, nil
	}
	return PeerState{}, nil
}

func ReadSysctlIPv4Forwarding() (string, error) {
	body, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return strings.TrimSpace(string(body)), err
}

func SetSysctlIPv4Forwarding(value string) error {
	if value != "0" && value != "1" {
		return errors.New("invalid IPv4 forwarding value")
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(value+"\n"), 0o644)
}

func FileSHA256(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func bounded(value []byte) string {
	text := strings.TrimSpace(string(value))
	if len(text) > 512 {
		text = text[:512]
	}
	if text == "" {
		return "host command returned an error"
	}
	return text
}

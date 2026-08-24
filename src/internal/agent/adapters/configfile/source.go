// File: src/internal/agent/adapters/configfile/source.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package configfile

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

const maxConfigBytes = 4 << 20

type Source struct {
	root           string
	allowed        func(string) bool
	fingerprintKey []byte
}

func New(root string, allowed func(string) bool) *Source {
	return &Source{root: root, allowed: allowed}
}

func NewWithFingerprint(root string, allowed func(string) bool, fingerprintKey []byte) *Source {
	return &Source{
		root: root, allowed: allowed,
		fingerprintKey: append([]byte(nil), fingerprintKey...),
	}
}

func (s *Source) Scan(ctx context.Context) ([]inventory.FileRecord, []inventory.DiagnosticIssue, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, nil, fmt.Errorf("read config root: %w", err)
	}

	records := make([]inventory.FileRecord, 0)
	issues := make([]inventory.DiagnosticIssue, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, issues, err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		if !s.allowed(name) {
			continue
		}

		path := filepath.Join(s.root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			issues = append(issues, fileIssue(name, "CONFIG_STAT_FAILED", err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			issues = append(issues, inventory.DiagnosticIssue{
				Code:        "CONFIG_SYMLINK_REJECTED",
				Severity:    "error",
				Summary:     fmt.Sprintf("WireGuard config for %s is a symlink", name),
				Remediation: "Replace it with a root-owned regular file before adoption.",
			})
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > maxConfigBytes {
			issues = append(issues, inventory.DiagnosticIssue{
				Code:        "CONFIG_TOO_LARGE",
				Severity:    "error",
				Summary:     fmt.Sprintf("WireGuard config for %s exceeds 4 MiB", name),
				Remediation: "Reduce the config size or leave the interface read-only.",
			})
			continue
		}

		record, parseIssues, err := s.readRecord(path, name)
		issues = append(issues, parseIssues...)
		if err != nil {
			issues = append(issues, fileIssue(name, "CONFIG_READ_FAILED", err))
			continue
		}
		records = append(records, inventory.FileRecord{Interface: record})
	}
	return records, issues, nil
}

func (s *Source) readRecord(path, name string) (inventory.Interface, []inventory.DiagnosticIssue, error) {
	file, err := os.Open(path)
	if err != nil {
		return inventory.Interface{}, nil, err
	}
	defer file.Close()

	hasher := sha256.New()
	limited := io.LimitReader(file, maxConfigBytes+1)
	body, err := io.ReadAll(io.TeeReader(limited, hasher))
	if err != nil {
		return inventory.Interface{}, nil, err
	}
	if len(body) > maxConfigBytes {
		return inventory.Interface{}, nil, errors.New("config exceeded limit while reading")
	}

	record := inventory.Interface{
		Name:           name,
		Backend:        "wg_quick",
		ManagementMode: "observed",
		ConfigPath:     path,
		ServiceUnit:    "wg-quick@" + name + ".service",
		FileHash:       hex.EncodeToString(hasher.Sum(nil)),
		DriftState:     "none",
		ConfigPresent:  true,
	}
	issues := parseRedacted(body, &record, s.fingerprintKey)
	return record, issues, nil
}

func parseRedacted(body []byte, record *inventory.Interface, fingerprintKey []byte) []inventory.DiagnosticIssue {
	var issues []inventory.DiagnosticIssue
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	section := ""
	var peer *inventory.Peer
	seenPublicKeys := make(map[string]struct{})
	flushPeer := func() {
		if peer == nil {
			return
		}
		if peer.PublicKey == "" {
			issues = append(issues, configIssue(record.Name, "PEER_PUBLIC_KEY_MISSING", "A peer block has no PublicKey."))
		} else if _, exists := seenPublicKeys[peer.PublicKey]; exists {
			issues = append(issues, configIssue(record.Name, "PEER_PUBLIC_KEY_DUPLICATE", "A peer PublicKey appears more than once."))
		} else {
			seenPublicKeys[peer.PublicKey] = struct{}{}
			if peer.Name == "" {
				peer.Name = shortKey(peer.PublicKey)
			}
			peer.ActivityState = "unknown"
			record.Peers = append(record.Peers, *peer)
		}
		peer = nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flushPeer()
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peer = &inventory.Peer{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "address":
				record.Addresses = append(record.Addresses, parseAddresses(value, "file", record.Name, &issues)...)
			case "saveconfig":
				record.SaveConfigDetected = strings.EqualFold(value, "true")
			case "privatekey":
				// Deliberately ignored. Never retain or format the value.
			}
		case "peer":
			if peer == nil {
				continue
			}
			switch key {
			case "publickey":
				if validKey(value) {
					peer.PublicKey = value
				} else {
					issues = append(issues, configIssue(record.Name, "PEER_PUBLIC_KEY_INVALID", "A peer PublicKey is not a 32-byte base64 key."))
				}
			case "allowedips":
				for _, item := range strings.Split(value, ",") {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
					if err != nil {
						issues = append(issues, configIssue(record.Name, "PEER_ALLOWED_IP_INVALID", "A peer AllowedIPs entry is invalid."))
						continue
					}
					peer.AllowedIPs = append(peer.AllowedIPs, prefix.Masked().String())
				}
			case "endpoint":
				peer.Endpoint = value
			case "persistentkeepalive":
				seconds, err := strconv.Atoi(value)
				if err == nil && seconds >= 0 && seconds <= 65535 {
					peer.PersistentKeepalive = seconds
				}
			case "presharedkey":
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil || len(decoded) != 32 {
					issues = append(issues, configIssue(record.Name, "PEER_PRESHARED_KEY_INVALID", "A peer PresharedKey is invalid."))
					continue
				}
				peer.PSKPresent = true
				if len(fingerprintKey) == 32 {
					peer.PSKFingerprint, _ = secret.Fingerprint(fingerprintKey, decoded)
				}
				clear(decoded)
			}
		}
	}
	flushPeer()
	if err := scanner.Err(); err != nil {
		issues = append(issues, configIssue(record.Name, "CONFIG_LINE_TOO_LONG", "The config contains a line larger than 1 MiB."))
	}
	return issues
}

func parseAddresses(value, source, interfaceName string, issues *[]inventory.DiagnosticIssue) []inventory.Address {
	var addresses []inventory.Address
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			*issues = append(*issues, configIssue(interfaceName, "INTERFACE_ADDRESS_INVALID", "An Interface Address entry is invalid."))
			continue
		}
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		addresses = append(addresses, inventory.Address{
			Family:       family,
			Address:      prefix.Addr().String(),
			PrefixLength: prefix.Bits(),
			Source:       source,
		})
	}
	return addresses
}

func validKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return false
	}
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

func shortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return "external-" + key[:8]
}

func configIssue(interfaceName, code, summary string) inventory.DiagnosticIssue {
	return inventory.DiagnosticIssue{
		Code:        code,
		Severity:    "warning",
		Summary:     fmt.Sprintf("%s: %s", interfaceName, summary),
		Remediation: "Inspect the root-owned config on the gateway; WireGate will not rewrite it.",
	}
}

func fileIssue(interfaceName, code string, err error) inventory.DiagnosticIssue {
	return inventory.DiagnosticIssue{
		Code:        code,
		Severity:    "error",
		Summary:     fmt.Sprintf("Could not inspect WireGuard config for %s: %s", interfaceName, err),
		Remediation: "Check the config path, ownership and permissions.",
	}
}

// File: src/internal/agent/configdoc/document.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

// Package configdoc implements the line-preserving wg-quick document model.
//
// The package deliberately separates the raw document from the redacted
// inventory parser. A Document owns the exact input bytes and only rewrites the
// assignment tokens selected by a caller. Parsing and serializing without a
// patch is therefore byte-for-byte lossless.
package configdoc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const DefaultMaxBytes = 4 << 20

var (
	ErrUnsupportedSyntax = errors.New("unsupported wg-quick syntax")
	ErrPeerNotFound      = errors.New("peer not found")
	ErrDuplicatePeer     = errors.New("duplicate peer public key")
)

type NodeKind uint8

const (
	RawLine NodeKind = iota
	BlankLine
	CommentLine
	SectionHeader
	Assignment
)

type Node struct {
	Kind    NodeKind
	Raw     []byte
	Section string
	Key     string
	Value   string

	valueStart int
	valueEnd   int
}

type Warning struct {
	Line    int
	Code    string
	Message string
}

type Peer struct {
	PublicKey           string
	PresharedKeyPresent bool
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive uint16

	blockStart int
	blockEnd   int
	fields     map[string]int
}

type Analysis struct {
	InterfaceCount    int
	PrivateKeyPresent bool
	SaveConfig        bool
	HasHooks          bool
	HasUnknown        bool
	Peers             []Peer
	Warnings          []Warning
}

type Document struct {
	raw      []byte
	nodes    []Node
	analysis Analysis
	newline  string
}

type PeerPatch struct {
	AllowedIPs          *[]string
	Endpoint            *string
	PersistentKeepalive *uint16
	PresharedKey        *string
}

type NewPeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive uint16
}

type PeerSecret struct {
	PublicKey    string
	PresharedKey []byte
}

func Parse(input []byte) (*Document, error) {
	if len(input) > DefaultMaxBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", DefaultMaxBytes)
	}
	document := &Document{
		raw:     bytes.Clone(input),
		newline: detectNewline(input),
	}
	document.nodes = parseNodes(input)
	document.analyze()
	return document, nil
}

func (d *Document) Bytes() []byte {
	return bytes.Clone(d.raw)
}

func (d *Document) Destroy() {
	clear(d.raw)
	for index := range d.nodes {
		clear(d.nodes[index].Raw)
		d.nodes[index].Value = ""
	}
	d.raw = nil
	d.nodes = nil
	d.analysis = Analysis{}
}

func (d *Document) Nodes() []Node {
	nodes := make([]Node, len(d.nodes))
	copy(nodes, d.nodes)
	for index := range nodes {
		nodes[index].Raw = bytes.Clone(nodes[index].Raw)
	}
	return nodes
}

func (d *Document) Analysis() Analysis {
	analysis := d.analysis
	analysis.Peers = append([]Peer(nil), d.analysis.Peers...)
	analysis.Warnings = append([]Warning(nil), d.analysis.Warnings...)
	for index := range analysis.Peers {
		analysis.Peers[index].AllowedIPs = append([]string(nil), analysis.Peers[index].AllowedIPs...)
		analysis.Peers[index].fields = nil
	}
	return analysis
}

// PeerSecrets returns decoded PSKs for the privileged secret service. Callers
// must encrypt or clear these byte slices immediately and must never expose
// them through inventory, RPC, logs, or formatting.
func (d *Document) PeerSecrets() ([]PeerSecret, error) {
	var result []PeerSecret
	for _, peer := range d.analysis.Peers {
		if !peer.PresharedKeyPresent {
			continue
		}
		nodeIndex, exists := peer.fields["presharedkey"]
		if !exists {
			continue
		}
		value := strings.TrimSpace(d.nodes[nodeIndex].Value)
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("peer %s has an invalid preshared key", peer.PublicKey)
		}
		result = append(result, PeerSecret{
			PublicKey: peer.PublicKey, PresharedKey: decoded,
		})
	}
	return result, nil
}

// AdoptionSafe enforces the syntax gates that must pass before WireGate can
// take ownership. Unknown keys remain preserved, but unknown sections or raw
// non-comment statements are treated as unsafe to patch automatically.
func (d *Document) AdoptionSafe() error {
	switch {
	case d.analysis.InterfaceCount != 1:
		return fmt.Errorf("%w: expected exactly one Interface section", ErrUnsupportedSyntax)
	case d.analysis.HasUnknown:
		return fmt.Errorf("%w: document contains an unknown section or raw statement", ErrUnsupportedSyntax)
	}
	for _, warning := range d.analysis.Warnings {
		switch warning.Code {
		case "DUPLICATE_PEER_PUBLIC_KEY":
			return fmt.Errorf("%w: %s", ErrDuplicatePeer, warning.Message)
		case "PEER_PUBLIC_KEY_MISSING", "PEER_PUBLIC_KEY_INVALID",
			"INTERFACE_PRIVATE_KEY_MISSING", "INTERFACE_PRIVATE_KEY_INVALID",
			"REPEATED_SECRET_KEY":
			return fmt.Errorf("%w: %s", ErrUnsupportedSyntax, warning.Message)
		}
	}
	return nil
}

func (d *Document) PatchPeer(publicKey string, patch PeerPatch) error {
	if err := d.AdoptionSafe(); err != nil {
		return err
	}
	peer, err := d.findPeer(publicKey)
	if err != nil {
		return err
	}
	replacements := make(map[string]*string)
	if patch.AllowedIPs != nil {
		value, err := canonicalPrefixes(*patch.AllowedIPs)
		if err != nil {
			return err
		}
		joined := strings.Join(value, ", ")
		replacements["allowedips"] = &joined
	}
	if patch.Endpoint != nil {
		value := strings.TrimSpace(*patch.Endpoint)
		replacements["endpoint"] = &value
	}
	if patch.PersistentKeepalive != nil {
		value := strconv.FormatUint(uint64(*patch.PersistentKeepalive), 10)
		replacements["persistentkeepalive"] = &value
	}
	if patch.PresharedKey != nil {
		if *patch.PresharedKey != "" {
			if err := validateKey(*patch.PresharedKey); err != nil {
				return fmt.Errorf("invalid preshared key: %w", err)
			}
		}
		value := strings.TrimSpace(*patch.PresharedKey)
		replacements["presharedkey"] = &value
	}

	block := make([]Node, peer.blockEnd-peer.blockStart)
	copy(block, d.nodes[peer.blockStart:peer.blockEnd])
	for _, key := range []string{"allowedips", "endpoint", "persistentkeepalive", "presharedkey"} {
		value, requested := replacements[key]
		if !requested {
			continue
		}
		var positions []int
		for index, node := range block {
			if node.Kind == Assignment && node.Key == key {
				positions = append(positions, index)
			}
		}
		if len(positions) > 0 {
			if *value != "" {
				block[positions[0]].Raw = replaceAssignmentValue(block[positions[0]], *value)
				block[positions[0]].Value = *value
				positions = positions[1:]
			}
			for index := len(positions) - 1; index >= 0; index-- {
				position := positions[index]
				block = append(block[:position], block[position+1:]...)
			}
			continue
		}
		if *value == "" {
			continue
		}
		keyName := displayKey(key)
		raw := []byte(keyName + " = " + *value + d.newline)
		block = append(block, Node{
			Kind:    Assignment,
			Raw:     raw,
			Section: "peer",
			Key:     key,
			Value:   *value,
		})
	}
	return d.replaceNodeRange(peer.blockStart, peer.blockEnd, renderNodes(block))
}

func (d *Document) AddPeer(peer NewPeer) error {
	if err := d.AdoptionSafe(); err != nil {
		return err
	}
	if err := validateKey(peer.PublicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if _, err := d.findPeer(peer.PublicKey); err == nil {
		return ErrDuplicatePeer
	} else if !errors.Is(err, ErrPeerNotFound) {
		return err
	}
	allowed, err := canonicalPrefixes(peer.AllowedIPs)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return errors.New("peer requires at least one AllowedIPs prefix")
	}
	if peer.PresharedKey != "" {
		if err := validateKey(peer.PresharedKey); err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
	}

	var block strings.Builder
	if len(d.raw) > 0 && !bytes.HasSuffix(d.raw, []byte("\n")) && !bytes.HasSuffix(d.raw, []byte("\r")) {
		block.WriteString(d.newline)
	}
	if len(d.raw) > 0 && !endsWithBlankLine(d.raw) {
		block.WriteString(d.newline)
	}
	block.WriteString("[Peer]")
	block.WriteString(d.newline)
	block.WriteString("PublicKey = ")
	block.WriteString(peer.PublicKey)
	block.WriteString(d.newline)
	if peer.PresharedKey != "" {
		block.WriteString("PresharedKey = ")
		block.WriteString(peer.PresharedKey)
		block.WriteString(d.newline)
	}
	block.WriteString("AllowedIPs = ")
	block.WriteString(strings.Join(allowed, ", "))
	block.WriteString(d.newline)
	if peer.Endpoint != "" {
		block.WriteString("Endpoint = ")
		block.WriteString(strings.TrimSpace(peer.Endpoint))
		block.WriteString(d.newline)
	}
	if peer.PersistentKeepalive != 0 {
		block.WriteString("PersistentKeepalive = ")
		block.WriteString(strconv.FormatUint(uint64(peer.PersistentKeepalive), 10))
		block.WriteString(d.newline)
	}
	return d.reparse(append(bytes.Clone(d.raw), []byte(block.String())...))
}

// RemovePeer returns the exact raw peer block for encrypted archival.
func (d *Document) RemovePeer(publicKey string) ([]byte, error) {
	if err := d.AdoptionSafe(); err != nil {
		return nil, err
	}
	peer, err := d.findPeer(publicKey)
	if err != nil {
		return nil, err
	}
	archived := renderNodes(d.nodes[peer.blockStart:peer.blockEnd])
	if err := d.replaceNodeRange(peer.blockStart, peer.blockEnd, nil); err != nil {
		return nil, err
	}
	return archived, nil
}

// RestorePeerBlock appends the exact encrypted/archive payload produced by
// RemovePeer. Only the separator needed to keep sections syntactically
// distinct may be added; every byte inside the archived peer block is kept.
func (d *Document) RestorePeerBlock(publicKey string, archived []byte) error {
	if err := d.AdoptionSafe(); err != nil {
		return err
	}
	if _, err := d.findPeer(publicKey); err == nil {
		return ErrDuplicatePeer
	} else if !errors.Is(err, ErrPeerNotFound) {
		return err
	}
	block, err := Parse(archived)
	if err != nil {
		return err
	}
	defer block.Destroy()
	if block.analysis.InterfaceCount != 0 || block.analysis.HasUnknown || len(block.analysis.Peers) != 1 ||
		block.analysis.Peers[0].PublicKey != publicKey {
		return fmt.Errorf("%w: archived payload is not the requested peer block", ErrUnsupportedSyntax)
	}
	for _, warning := range block.analysis.Warnings {
		switch warning.Code {
		case "DUPLICATE_PEER_PUBLIC_KEY", "PEER_PUBLIC_KEY_MISSING", "PEER_PUBLIC_KEY_INVALID", "REPEATED_SECRET_KEY":
			return fmt.Errorf("%w: archived peer block is unsafe", ErrUnsupportedSyntax)
		}
	}
	output := bytes.Clone(d.raw)
	if len(output) > 0 && !bytes.HasSuffix(output, []byte("\n")) && !bytes.HasSuffix(output, []byte("\r")) {
		output = append(output, []byte(d.newline)...)
	}
	if len(output) > 0 && !endsWithBlankLine(output) {
		output = append(output, []byte(d.newline)...)
	}
	output = append(output, archived...)
	return d.reparse(output)
}

func (d *Document) findPeer(publicKey string) (Peer, error) {
	for _, peer := range d.analysis.Peers {
		if peer.PublicKey == publicKey {
			return peer, nil
		}
	}
	return Peer{}, ErrPeerNotFound
}

func (d *Document) replaceNodeRange(start, end int, replacement []byte) error {
	var output bytes.Buffer
	output.Write(renderNodes(d.nodes[:start]))
	output.Write(replacement)
	output.Write(renderNodes(d.nodes[end:]))
	return d.reparse(output.Bytes())
}

func (d *Document) reparse(raw []byte) error {
	parsed, err := Parse(raw)
	if err != nil {
		return err
	}
	*d = *parsed
	return nil
}

func (d *Document) analyze() {
	knownInterface := map[string]bool{
		"privatekey": true, "address": true, "listenport": true, "fwmark": true,
		"dns": true, "mtu": true, "table": true, "preup": true, "postup": true,
		"predown": true, "postdown": true, "saveconfig": true,
	}
	knownPeer := map[string]bool{
		"publickey": true, "presharedkey": true, "allowedips": true,
		"endpoint": true, "persistentkeepalive": true,
	}

	var currentPeer *Peer
	privateKeyCount := 0
	finishPeer := func(end int) {
		if currentPeer == nil {
			return
		}
		currentPeer.blockEnd = end
		switch {
		case currentPeer.PublicKey == "":
			d.analysis.Warnings = append(d.analysis.Warnings, Warning{
				Line: currentPeer.blockStart + 1, Code: "PEER_PUBLIC_KEY_MISSING",
				Message: "Peer section has no valid PublicKey",
			})
		default:
			for _, existing := range d.analysis.Peers {
				if existing.PublicKey == currentPeer.PublicKey {
					d.analysis.Warnings = append(d.analysis.Warnings, Warning{
						Line: currentPeer.blockStart + 1, Code: "DUPLICATE_PEER_PUBLIC_KEY",
						Message: "Peer PublicKey appears more than once",
					})
					break
				}
			}
			d.analysis.Peers = append(d.analysis.Peers, *currentPeer)
		}
		currentPeer = nil
	}

	for index, node := range d.nodes {
		if node.Kind == SectionHeader {
			finishPeer(index)
			switch node.Section {
			case "interface":
				d.analysis.InterfaceCount++
			case "peer":
				currentPeer = &Peer{blockStart: index, fields: make(map[string]int)}
			default:
				d.analysis.HasUnknown = true
				d.analysis.Warnings = append(d.analysis.Warnings, Warning{
					Line: index + 1, Code: "UNKNOWN_SECTION",
					Message: "Unknown section " + node.Section + " is preserved but blocks adoption",
				})
			}
			continue
		}
		switch node.Kind {
		case RawLine:
			d.analysis.HasUnknown = true
			d.analysis.Warnings = append(d.analysis.Warnings, Warning{
				Line: index + 1, Code: "UNPARSED_STATEMENT",
				Message: "Unparsed statement is preserved but blocks adoption",
			})
		case Assignment:
			switch node.Section {
			case "interface":
				if !knownInterface[node.Key] {
					d.analysis.Warnings = append(d.analysis.Warnings, Warning{
						Line: index + 1, Code: "UNKNOWN_INTERFACE_KEY",
						Message: "Unknown Interface key is preserved",
					})
				}
				switch node.Key {
				case "privatekey":
					privateKeyCount++
					if privateKeyCount > 1 {
						d.analysis.Warnings = append(d.analysis.Warnings, Warning{
							Line: index + 1, Code: "REPEATED_SECRET_KEY",
							Message: "Repeated Interface PrivateKey is unsafe to adopt",
						})
					} else if err := validateKey(node.Value); err != nil {
						d.analysis.Warnings = append(d.analysis.Warnings, Warning{
							Line: index + 1, Code: "INTERFACE_PRIVATE_KEY_INVALID",
							Message: "Interface PrivateKey is not a non-zero 32-byte base64 key",
						})
					} else {
						d.analysis.PrivateKeyPresent = true
					}
				case "saveconfig":
					d.analysis.SaveConfig = strings.EqualFold(strings.TrimSpace(node.Value), "true")
				case "preup", "postup", "predown", "postdown":
					d.analysis.HasHooks = true
				}
			case "peer":
				if !knownPeer[node.Key] {
					d.analysis.Warnings = append(d.analysis.Warnings, Warning{
						Line: index + 1, Code: "UNKNOWN_PEER_KEY",
						Message: "Unknown Peer key is preserved",
					})
				}
				if currentPeer == nil {
					continue
				}
				if _, repeated := currentPeer.fields[node.Key]; !repeated {
					currentPeer.fields[node.Key] = index
				} else if node.Key == "publickey" || node.Key == "presharedkey" {
					d.analysis.Warnings = append(d.analysis.Warnings, Warning{
						Line: index + 1, Code: "REPEATED_SECRET_KEY",
						Message: "Repeated peer identity/secret key is unsafe to adopt",
					})
				}
				switch node.Key {
				case "publickey":
					if err := validateKey(node.Value); err != nil {
						d.analysis.Warnings = append(d.analysis.Warnings, Warning{
							Line: index + 1, Code: "PEER_PUBLIC_KEY_INVALID",
							Message: "Peer PublicKey is not a non-zero 32-byte base64 key",
						})
					} else {
						currentPeer.PublicKey = strings.TrimSpace(node.Value)
					}
				case "presharedkey":
					currentPeer.PresharedKeyPresent = strings.TrimSpace(node.Value) != ""
				case "allowedips":
					for _, item := range strings.Split(node.Value, ",") {
						if prefix, err := netip.ParsePrefix(strings.TrimSpace(item)); err == nil {
							currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, prefix.Masked().String())
						}
					}
				case "endpoint":
					currentPeer.Endpoint = strings.TrimSpace(node.Value)
				case "persistentkeepalive":
					if value, err := strconv.ParseUint(strings.TrimSpace(node.Value), 10, 16); err == nil {
						currentPeer.PersistentKeepalive = uint16(value)
					}
				}
			default:
				d.analysis.HasUnknown = true
				d.analysis.Warnings = append(d.analysis.Warnings, Warning{
					Line: index + 1, Code: "ASSIGNMENT_OUTSIDE_SECTION",
					Message: "Assignment outside a known section blocks adoption",
				})
			}
		}
	}
	finishPeer(len(d.nodes))
	if d.analysis.InterfaceCount == 1 && privateKeyCount == 0 {
		d.analysis.Warnings = append(d.analysis.Warnings, Warning{
			Code:    "INTERFACE_PRIVATE_KEY_MISSING",
			Message: "Interface section has no PrivateKey",
		})
	}
}

func parseNodes(input []byte) []Node {
	lines := splitLines(input)
	nodes := make([]Node, 0, len(lines))
	section := ""
	for _, raw := range lines {
		body := trimNewline(raw)
		trimmed := strings.TrimSpace(string(body))
		node := Node{Kind: RawLine, Raw: bytes.Clone(raw), Section: section}
		switch {
		case trimmed == "":
			node.Kind = BlankLine
		case strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			node.Kind = CommentLine
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			node.Kind = SectionHeader
			node.Section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			section = node.Section
		default:
			equal := bytes.IndexByte(body, '=')
			if equal >= 0 {
				key := strings.ToLower(strings.TrimSpace(string(body[:equal])))
				if key != "" {
					start := equal + 1
					for start < len(body) && (body[start] == ' ' || body[start] == '\t') {
						start++
					}
					end := len(body)
					for end > start && (body[end-1] == ' ' || body[end-1] == '\t') {
						end--
					}
					node.Kind = Assignment
					node.Key = key
					node.Value = string(body[start:end])
					node.valueStart = start
					node.valueEnd = end
				}
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func splitLines(input []byte) [][]byte {
	if len(input) == 0 {
		return nil
	}
	var lines [][]byte
	for len(input) > 0 {
		index := bytes.IndexByte(input, '\n')
		if index < 0 {
			lines = append(lines, input)
			break
		}
		lines = append(lines, input[:index+1])
		input = input[index+1:]
	}
	return lines
}

func trimNewline(raw []byte) []byte {
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	raw = bytes.TrimSuffix(raw, []byte("\r"))
	return raw
}

func replaceAssignmentValue(node Node, value string) []byte {
	raw := node.Raw
	bodyLength := len(trimNewline(raw))
	if node.valueStart > bodyLength || node.valueEnd > bodyLength {
		return bytes.Clone(raw)
	}
	result := make([]byte, 0, len(raw)-node.valueEnd+node.valueStart+len(value))
	result = append(result, raw[:node.valueStart]...)
	result = append(result, value...)
	result = append(result, raw[node.valueEnd:]...)
	return result
}

func renderNodes(nodes []Node) []byte {
	var result []byte
	for _, node := range nodes {
		result = append(result, node.Raw...)
	}
	return result
}

func detectNewline(input []byte) string {
	if bytes.Contains(input, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func endsWithBlankLine(input []byte) bool {
	return bytes.HasSuffix(input, []byte("\n\n")) || bytes.HasSuffix(input, []byte("\r\n\r\n"))
}

func validateKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return errors.New("key must decode to exactly 32 bytes")
	}
	var nonzero byte
	for _, item := range decoded {
		nonzero |= item
	}
	if nonzero == 0 {
		return errors.New("key cannot be all zero")
	}
	return nil
}

func canonicalPrefixes(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", value)
		}
		canonical := prefix.Masked().String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func displayKey(key string) string {
	switch key {
	case "allowedips":
		return "AllowedIPs"
	case "endpoint":
		return "Endpoint"
	case "persistentkeepalive":
		return "PersistentKeepalive"
	case "presharedkey":
		return "PresharedKey"
	default:
		return key
	}
}

// File: src/internal/agent/inventory/model.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package inventory

import (
	"context"
	"errors"
	"time"
)

var ErrUnsupported = errors.New("source unsupported on this platform")

type SourceStatus struct {
	Ready bool
	Error string
}

type DiagnosticIssue struct {
	Code        string
	Severity    string
	Summary     string
	Remediation string
}

type Snapshot struct {
	Interfaces    []Interface
	ConfigSource  SourceStatus
	RuntimeSource SourceStatus
	AddressSource SourceStatus
	Issues        []DiagnosticIssue
	RefreshedAt   time.Time
}

type Interface struct {
	Name               string
	Backend            string
	ManagementMode     string
	ConfigPath         string
	ServiceUnit        string
	FileHash           string
	RuntimeFingerprint string
	DriftState         string
	ConfigPresent      bool
	RuntimePresent     bool
	SaveConfigDetected bool
	Addresses          []Address
	Peers              []Peer
}

type Address struct {
	Family       int
	Address      string
	PrefixLength int
	Source       string
}

type Peer struct {
	Name                string
	PublicKey           string
	Endpoint            string
	PersistentKeepalive int
	AllowedIPs          []string
	LatestHandshakeAt   time.Time
	TransferRXBytes     uint64
	TransferTXBytes     uint64
	RuntimeSeenAt       time.Time
	ActivityState       string
	PSKPresent          bool
	PSKFingerprint      []byte
}

type FileRecord struct {
	Interface
}

type RuntimeRecord struct {
	Interface
}

type FileSource interface {
	Scan(context.Context) ([]FileRecord, []DiagnosticIssue, error)
}

type RuntimeSource interface {
	List(context.Context) ([]RuntimeRecord, error)
}

type AddressSource interface {
	List(context.Context, []string) (map[string][]Address, error)
}

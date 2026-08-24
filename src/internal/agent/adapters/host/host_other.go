//go:build !linux

// File: src/internal/agent/adapters/host/host_other.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package host

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
)

var errUnsupported = errors.New("Linux host control is unavailable on this platform")

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

func RequireNativeTools(bool) error                                 { return errUnsupported }
func LockInterface(string) (func() error, error)                    { return nil, errUnsupported }
func ManagedNFTConflict(context.Context) (string, error)            { return "", errUnsupported }
func InterfaceExists(string) (bool, error)                          { return false, errUnsupported }
func OccupiedPrefixes() ([]netip.Prefix, error)                     { return nil, errUnsupported }
func UDPPortAvailable(uint16) error                                 { return errUnsupported }
func WriteOwnedFile(string, []byte, fs.FileMode, fs.FileMode) error { return errUnsupported }
func RemoveOwnedFile(string, string) error                          { return errUnsupported }
func ValidateNFT(context.Context, string) error                     { return errUnsupported }
func ApplyNFT(context.Context, string) error                        { return errUnsupported }
func StartService(context.Context, string) error                    { return errUnsupported }
func StopService(context.Context, string) error                     { return errUnsupported }
func EnableService(context.Context, string) error                   { return errUnsupported }
func DisableService(context.Context, string) error                  { return errUnsupported }
func ServiceActive(context.Context, string) bool                    { return false }
func ServiceEnabled(context.Context, string) bool                   { return false }
func InspectDevice(string) (DeviceState, error)                     { return DeviceState{}, errUnsupported }
func InspectPeer(string, string) (PeerState, error)                 { return PeerState{}, errUnsupported }
func ReadSysctlIPv4Forwarding() (string, error)                     { return "", errUnsupported }
func SetSysctlIPv4Forwarding(string) error                          { return errUnsupported }
func FileSHA256(string) (string, error)                             { return "", errUnsupported }

//go:build !linux

// File: src/internal/agent/adapters/wgctrl/mutate_other.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package wgctrl

import (
	"context"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

func ApplyPeer(context.Context, string, PeerSpec) error {
	return inventory.ErrUnsupported
}

func RemovePeer(context.Context, string, string) error {
	return inventory.ErrUnsupported
}

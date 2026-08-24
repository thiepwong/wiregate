//go:build !linux

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

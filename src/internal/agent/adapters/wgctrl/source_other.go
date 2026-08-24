//go:build !linux

// File: src/internal/agent/adapters/wgctrl/source_other.go
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

type Source struct{}

func New() *Source {
	return &Source{}
}

func (s *Source) List(context.Context) ([]inventory.RuntimeRecord, error) {
	return nil, inventory.ErrUnsupported
}

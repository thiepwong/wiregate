//go:build !linux

// File: src/internal/agent/adapters/netlink/source_other.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package netlink

import (
	"context"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

type Source struct{}

func New() *Source {
	return &Source{}
}

func (s *Source) List(context.Context, []string) (map[string][]inventory.Address, error) {
	return nil, inventory.ErrUnsupported
}

//go:build linux

// File: src/internal/agent/adapters/netlink/source_linux.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package netlink

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

type Source struct{}

func New() *Source {
	return &Source{}
}

func (s *Source) List(ctx context.Context, names []string) (map[string][]inventory.Address, error) {
	result := make(map[string][]inventory.Address, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			continue
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", name, err)
		}
		for _, address := range addresses {
			if address.IPNet == nil {
				continue
			}
			ones, bits := address.IPNet.Mask.Size()
			family := 6
			if bits == 32 {
				family = 4
			}
			result[name] = append(result[name], inventory.Address{
				Family:       family,
				Address:      address.IP.String(),
				PrefixLength: ones,
				Source:       "runtime",
			})
		}
	}
	return result, nil
}

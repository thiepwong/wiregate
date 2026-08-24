//go:build !linux

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

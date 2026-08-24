//go:build !linux

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

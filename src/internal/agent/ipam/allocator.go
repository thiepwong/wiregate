package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

const maxAllocationScan = 1 << 20

type CandidateSet struct {
	Pool         netip.Prefix
	Gateway      netip.Addr
	Allocated    map[netip.Addr]struct{}
	Quarantined  map[netip.Addr]struct{}
	Reservations map[netip.Addr]struct{}
}

func Allocate(input CandidateSet) (netip.Addr, error) {
	pool := input.Pool.Masked()
	if !pool.IsValid() {
		return netip.Addr{}, errors.New("address pool is invalid")
	}
	if !input.Gateway.IsValid() || !pool.Contains(input.Gateway) {
		return netip.Addr{}, errors.New("gateway address must belong to the pool")
	}
	candidate := pool.Addr()
	for scanned := 0; candidate.IsValid() && pool.Contains(candidate) && scanned < maxAllocationScan; scanned++ {
		if usable(pool, candidate, input.Gateway) &&
			!contains(input.Allocated, candidate) &&
			!contains(input.Quarantined, candidate) &&
			!contains(input.Reservations, candidate) {
			return candidate, nil
		}
		candidate = candidate.Next()
	}
	if candidate.IsValid() && pool.Contains(candidate) {
		return netip.Addr{}, fmt.Errorf("allocation scan exceeded %d candidates", maxAllocationScan)
	}
	return netip.Addr{}, errors.New("address pool is exhausted")
}

func ValidatePool(pool netip.Prefix, gateway netip.Addr, occupied []netip.Prefix) error {
	pool = pool.Masked()
	if !pool.IsValid() || !gateway.IsValid() || !pool.Contains(gateway) {
		return errors.New("invalid pool or gateway")
	}
	for _, prefix := range occupied {
		if pool.Addr().BitLen() == prefix.Addr().BitLen() && pool.Overlaps(prefix) {
			return fmt.Errorf("pool %s overlaps occupied prefix %s", pool, prefix)
		}
	}
	return nil
}

func usable(pool netip.Prefix, candidate, gateway netip.Addr) bool {
	if candidate == gateway || candidate == pool.Addr() {
		return false
	}
	if candidate.Is4() {
		broadcast := lastAddress(pool)
		if candidate == broadcast {
			return false
		}
	}
	return true
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	raw := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		byteIndex := bit / 8
		bitIndex := 7 - (bit % 8)
		raw[byteIndex] |= 1 << bitIndex
	}
	return netip.AddrFrom4(raw)
}

func contains(values map[netip.Addr]struct{}, value netip.Addr) bool {
	_, exists := values[value]
	return exists
}

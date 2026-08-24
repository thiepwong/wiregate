package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type PersistResult struct {
	InterfaceCount int
	PeerCount      int
}

type Store interface {
	ReplaceInventory(context.Context, Snapshot) (PersistResult, error)
}

type Service struct {
	files     FileSource
	runtime   RuntimeSource
	addresses AddressSource
	store     Store
	allowed   func(string) bool
	now       func() time.Time

	mu          sync.RWMutex
	diagnostics Snapshot
}

func NewService(
	files FileSource,
	runtime RuntimeSource,
	addresses AddressSource,
	store Store,
	allowed func(string) bool,
) *Service {
	return &Service{
		files:     files,
		runtime:   runtime,
		addresses: addresses,
		store:     store,
		allowed:   allowed,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Refresh(ctx context.Context) (PersistResult, error) {
	refreshedAt := s.now()
	snapshot := Snapshot{RefreshedAt: refreshedAt}

	fileRecords, fileIssues, fileErr := s.files.Scan(ctx)
	snapshot.Issues = append(snapshot.Issues, fileIssues...)
	snapshot.ConfigSource = sourceStatus(fileErr)
	if fileErr != nil {
		snapshot.Issues = append(snapshot.Issues, sourceIssue("CONFIG_SOURCE_UNAVAILABLE", fileErr))
	}

	runtimeRecords, runtimeErr := s.runtime.List(ctx)
	snapshot.RuntimeSource = sourceStatus(runtimeErr)
	if runtimeErr != nil && !errors.Is(runtimeErr, ErrUnsupported) {
		snapshot.Issues = append(snapshot.Issues, sourceIssue("RUNTIME_SOURCE_UNAVAILABLE", runtimeErr))
	}

	merged := make(map[string]*Interface, len(fileRecords)+len(runtimeRecords))
	for _, fileRecord := range fileRecords {
		record := fileRecord.Interface
		if !s.allowed(record.Name) {
			continue
		}
		copy := record
		merged[record.Name] = &copy
	}
	for _, runtimeRecord := range runtimeRecords {
		record := runtimeRecord.Interface
		if !s.allowed(record.Name) {
			continue
		}
		if current, exists := merged[record.Name]; exists {
			mergeRuntime(current, record)
		} else {
			copy := record
			merged[record.Name] = &copy
		}
	}

	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)

	addressMap, addressErr := s.addresses.List(ctx, names)
	snapshot.AddressSource = sourceStatus(addressErr)
	if addressErr != nil && !errors.Is(addressErr, ErrUnsupported) {
		snapshot.Issues = append(snapshot.Issues, sourceIssue("ADDRESS_SOURCE_UNAVAILABLE", addressErr))
	}

	snapshot.Interfaces = make([]Interface, 0, len(names))
	for _, name := range names {
		record := merged[name]
		record.Addresses = mergeAddresses(record.Addresses, addressMap[name])
		snapshot.Interfaces = append(snapshot.Interfaces, *record)
	}

	result, err := s.store.ReplaceInventory(ctx, snapshot)
	if err != nil {
		snapshot.Issues = append(snapshot.Issues, DiagnosticIssue{
			Code:        "INVENTORY_PERSIST_FAILED",
			Severity:    "critical",
			Summary:     "Could not persist the redacted WireGuard inventory.",
			Remediation: "Check agent database health and disk space.",
		})
		s.setDiagnostics(snapshot)
		return PersistResult{}, fmt.Errorf("persist inventory: %w", err)
	}
	s.setDiagnostics(snapshot)
	return result, nil
}

func (s *Service) Diagnostics() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.diagnostics)
}

func (s *Service) setDiagnostics(snapshot Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diagnostics = cloneSnapshot(snapshot)
}

func mergeRuntime(target *Interface, runtime Interface) {
	target.RuntimePresent = true
	target.RuntimeFingerprint = runtime.RuntimeFingerprint
	target.DriftState = "unknown"
	if !target.ConfigPresent {
		target.Backend = "runtime_only"
	}

	filePeers := make(map[string]Peer, len(target.Peers))
	for _, peer := range target.Peers {
		filePeers[peer.PublicKey] = peer
	}
	target.Peers = make([]Peer, 0, len(filePeers)+len(runtime.Peers))
	for _, peer := range runtime.Peers {
		if filePeer, exists := filePeers[peer.PublicKey]; exists {
			if filePeer.Name != "" {
				peer.Name = filePeer.Name
			}
			if len(peer.AllowedIPs) == 0 {
				peer.AllowedIPs = filePeer.AllowedIPs
			}
			peer.PSKPresent = filePeer.PSKPresent
			peer.PSKFingerprint = append([]byte(nil), filePeer.PSKFingerprint...)
			delete(filePeers, peer.PublicKey)
		}
		target.Peers = append(target.Peers, peer)
	}
	for _, peer := range filePeers {
		peer.ActivityState = "unknown"
		target.Peers = append(target.Peers, peer)
	}
	sort.Slice(target.Peers, func(i, j int) bool {
		return target.Peers[i].PublicKey < target.Peers[j].PublicKey
	})
}

func mergeAddresses(left, right []Address) []Address {
	result := make([]Address, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, group := range [][]Address{left, right} {
		for _, address := range group {
			key := fmt.Sprintf("%d/%s/%d", address.Family, address.Address, address.PrefixLength)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		if result[i].Address != result[j].Address {
			return result[i].Address < result[j].Address
		}
		return result[i].PrefixLength < result[j].PrefixLength
	})
	return result
}

func sourceStatus(err error) SourceStatus {
	if err == nil {
		return SourceStatus{Ready: true}
	}
	return SourceStatus{Error: err.Error()}
}

func sourceIssue(code string, err error) DiagnosticIssue {
	return DiagnosticIssue{
		Code:        code,
		Severity:    "warning",
		Summary:     err.Error(),
		Remediation: "Inspect agent permissions and host support; discovery remains read-only.",
	}
}

func cloneSnapshot(source Snapshot) Snapshot {
	clone := source
	clone.Interfaces = make([]Interface, len(source.Interfaces))
	for index, item := range source.Interfaces {
		clone.Interfaces[index] = item
		clone.Interfaces[index].Addresses = append([]Address(nil), item.Addresses...)
		clone.Interfaces[index].Peers = make([]Peer, len(item.Peers))
		for peerIndex, peer := range item.Peers {
			clone.Interfaces[index].Peers[peerIndex] = peer
			clone.Interfaces[index].Peers[peerIndex].AllowedIPs = append([]string(nil), peer.AllowedIPs...)
			clone.Interfaces[index].Peers[peerIndex].PSKFingerprint = append([]byte(nil), peer.PSKFingerprint...)
		}
	}
	clone.Issues = append([]DiagnosticIssue(nil), source.Issues...)
	return clone
}

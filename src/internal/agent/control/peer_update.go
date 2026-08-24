// File: src/internal/agent/control/peer_update.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	wgadapter "github.com/wiregate-project/wiregate/internal/agent/adapters/wgctrl"
	"github.com/wiregate-project/wiregate/internal/agent/configdoc"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/agent/validation"
)

type PeerUpdateRequest struct {
	PeerID              string
	Name                *string
	ServerAllowedIPs    []string
	ClientRoutes        []string
	Endpoint            *string
	PersistentKeepalive *uint16
}

type peerUpdateIntent struct {
	PeerID              string   `json:"peer_id"`
	Name                string   `json:"name"`
	ServerAllowedIPs    []string `json:"server_allowed_ips"`
	ClientRoutes        []string `json:"client_routes"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive uint16   `json:"persistent_keepalive"`
	UpdateName          bool     `json:"update_name"`
	UpdateAllowedIPs    bool     `json:"update_allowed_ips"`
	UpdateClientRoutes  bool     `json:"update_client_routes"`
	UpdateEndpoint      bool     `json:"update_endpoint"`
	UpdateKeepalive     bool     `json:"update_keepalive"`
}

type peerUpdateSnapshot struct {
	Version  int              `json:"version"`
	Intent   peerUpdateIntent `json:"intent"`
	Original []byte           `json:"original_config"`
	Proposed []byte           `json:"proposed_config"`
}

func (s *Service) PreviewUpdatePeer(
	ctx context.Context,
	request PeerUpdateRequest,
	expectedRevision int64,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor, "client:manage", false); err != nil {
		return Preview{}, err
	}
	intent, peer, interfaceRecord, config, err := s.preflightPeerUpdate(ctx, request, expectedRevision)
	if err != nil {
		return Preview{}, err
	}
	wipe(config.Body)
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		return Preview{}, err
	}
	expected := expectedRevision
	expiresAt := s.now().Add(5 * time.Minute)
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		InterfaceID: interfaceRecord.ID, Type: "update_peer", IntentJSON: string(intentJSON),
		IdempotencyKey: actor.IdempotencyKey, ActorID: actor.ID, ActorRole: actor.Role,
		RequestID: actor.RequestID, Reason: actor.Reason, ExpectedRevision: &expected,
		OriginalFileHash: interfaceRecord.FileHash, OriginalRuntimeHash: interfaceRecord.RuntimeFingerprint,
		ProposedDiffJSON: fmt.Sprintf(
			`{"peer_id":%q,"name":%q,"allowed_ips":%q,"endpoint":%q,"keepalive":%d}`,
			peer.ID, intent.Name, strings.Join(intent.ServerAllowedIPs, ","),
			intent.Endpoint, intent.PersistentKeepalive,
		),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return Preview{
		OperationID: operation.ID, OperationType: "update_peer", BaseRevision: expectedRevision,
		SemanticDiffJSON:    operation.ProposedDiffJSON,
		TextualDiffRedacted: fmt.Sprintf("update peer %s without restarting %s", peer.Name, interfaceRecord.Name),
		Disruptive:          false, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) CommitUpdatePeer(
	ctx context.Context,
	operationID string,
	actor Actor,
) (Result, error) {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return Result{}, ErrNotFound
	}
	if metadata.Type != "update_peer" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || actor.Permission != "client:manage" {
		return Result{}, ErrPermission
	}
	if metadata.State == agentoperation.StateCommitted {
		return Result{OperationID: operationID, State: metadata.State, InterfaceID: metadata.InterfaceID}, nil
	}
	if metadata.State != agentoperation.StatePending || metadata.ExpectedRevision == nil ||
		agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		return Result{}, fmt.Errorf("%w: peer update preview expired", ErrConflict)
	}
	var intent peerUpdateIntent
	if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil {
		return Result{}, fmt.Errorf("%w: invalid peer update intent", ErrInvalid)
	}
	request := PeerUpdateRequest{PeerID: intent.PeerID}
	if intent.UpdateName {
		request.Name = &intent.Name
	}
	if intent.UpdateAllowedIPs {
		request.ServerAllowedIPs = intent.ServerAllowedIPs
	}
	if intent.UpdateClientRoutes {
		request.ClientRoutes = intent.ClientRoutes
	}
	if intent.UpdateEndpoint {
		request.Endpoint = &intent.Endpoint
	}
	if intent.UpdateKeepalive {
		request.PersistentKeepalive = &intent.PersistentKeepalive
	}
	_, peer, interfaceRecord, config, err := s.preflightPeerUpdate(ctx, request, *metadata.ExpectedRevision)
	if err != nil {
		return Result{}, err
	}
	defer wipe(config.Body)
	unlock, err := s.lockInterface(interfaceRecord.Name)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if config.Hash != metadata.OriginalFileHash {
		return Result{}, ErrConflict
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return Result{}, ErrConflict
	}
	return s.executePeerUpdate(ctx, operationID, intent, peer, interfaceRecord, config)
}

func (s *Service) executePeerUpdate(
	ctx context.Context,
	operationID string,
	intent peerUpdateIntent,
	peer repository.PeerRecord,
	interfaceRecord repository.InterfaceRecord,
	config filesystem.ConfigFile,
) (Result, error) {
	document, err := configdoc.Parse(config.Body)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_PARSE_FAILED")
		return Result{}, err
	}
	defer document.Destroy()
	patch := configdoc.PeerPatch{}
	if intent.UpdateAllowedIPs {
		allowed := append([]string(nil), intent.ServerAllowedIPs...)
		patch.AllowedIPs = &allowed
	}
	if intent.UpdateEndpoint {
		endpoint := intent.Endpoint
		patch.Endpoint = &endpoint
	}
	if intent.UpdateKeepalive {
		keepalive := intent.PersistentKeepalive
		patch.PersistentKeepalive = &keepalive
	}
	if err := document.PatchPeer(peer.PublicKey, patch); err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_PATCH_FAILED")
		return Result{}, err
	}
	proposed := document.Bytes()
	defer wipe(proposed)
	snapshot := peerUpdateSnapshot{
		Version: 1, Intent: intent, Original: config.Body, Proposed: proposed,
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipe(payload)
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{
		GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload",
	}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	if err := s.repository.SnapshotOperation(
		ctx, operationID, secretContext, envelope,
		config.Hash, interfaceRecord.RuntimeFingerprint, nil,
	); err != nil {
		s.rejectValidated(ctx, operationID, "PEER_UPDATE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil,
	); err != nil {
		return Result{}, err
	}
	material, err := s.repository.ClientMaterial(ctx, peer.ID)
	if err != nil {
		return Result{}, errors.Join(err, s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, nil, &snapshot, false))
	}
	var psk []byte
	if material.PresharedKey != nil {
		psk, err = s.openPeerSecret(material.PresharedKey)
		if err != nil {
			return Result{}, errors.Join(err, s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, nil, &snapshot, false))
		}
		defer wipe(psk)
	}
	active := interfaceRecord.RuntimePresent
	if active {
		if err := wgadapter.ApplyPeer(ctx, interfaceRecord.Name, wgadapter.PeerSpec{
			PublicKey: peer.PublicKey, PresharedKey: psk, AllowedIPs: intent.ServerAllowedIPs,
			Endpoint: intent.Endpoint, PersistentKeepalive: intent.PersistentKeepalive,
		}); err != nil {
			return Result{}, errors.Join(err, s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, psk, &snapshot, false))
		}
	}
	fileChanged := !bytes.Equal(config.Body, proposed)
	if fileChanged {
		if _, err := s.files.ExchangeConfig(interfaceRecord.Name, config.Hash, proposed); err != nil {
			return Result{}, errors.Join(err, s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, psk, &snapshot, false))
		}
	}
	if active {
		state, inspectErr := host.InspectPeer(interfaceRecord.Name, peer.PublicKey)
		if inspectErr != nil || !state.Present || !samePrefixes(state.AllowedIPs, intent.ServerAllowedIPs) {
			return Result{}, errors.Join(errors.New("peer update verification failed"), inspectErr,
				s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, psk, &snapshot, fileChanged))
		}
	}
	device, _ := host.InspectDevice(interfaceRecord.Name)
	revision, err := s.repository.CompletePeerUpdate(ctx, operationID, repository.PeerUpdateInput{
		PeerID: peer.ID, InterfaceID: interfaceRecord.ID, Name: intent.Name,
		Endpoint: intent.Endpoint, PersistentKeepalive: int(intent.PersistentKeepalive),
		AllowedIPs: intent.ServerAllowedIPs, ClientRoutes: intent.ClientRoutes,
		OriginalFileHash: config.Hash, ProposedFileHash: filesystem.SHA256(proposed),
		RuntimeFingerprint: device.Fingerprint,
	})
	if err != nil {
		return Result{}, errors.Join(err, s.rollbackPeerUpdate(ctx, operationID, interfaceRecord, peer, psk, &snapshot, fileChanged))
	}
	if err := s.repository.FinalizeControlOperation(
		ctx, operationID, "update_peer", "peer", peer.ID,
		interfaceRecord.Revision, revision,
	); err != nil {
		return Result{}, err
	}
	return Result{
		OperationID: operationID, State: agentoperation.StateCommitted,
		InterfaceID: interfaceRecord.ID, InterfaceRevision: revision,
		EffectiveNextBoot: !active,
	}, nil
}

func (s *Service) preflightPeerUpdate(
	ctx context.Context,
	request PeerUpdateRequest,
	expectedRevision int64,
) (peerUpdateIntent, repository.PeerRecord, repository.InterfaceRecord, filesystem.ConfigFile, error) {
	peer, err := s.repository.GetPeer(ctx, strings.TrimSpace(request.PeerID))
	if err != nil {
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrNotFound
	}
	if peer.LifecycleState != "active" {
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrPrecondition
	}
	interfaceRecord, err := s.repository.GetInterface(ctx, peer.InterfaceID)
	if err != nil {
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, err
	}
	if (interfaceRecord.ManagementMode != "managed" && interfaceRecord.ManagementMode != "adopted") ||
		interfaceRecord.Revision != expectedRevision || interfaceRecord.DriftState != "none" || !interfaceRecord.ConfigPresent {
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrConflict
	}
	config, err := s.files.ReadConfig(interfaceRecord.Name)
	if err != nil || config.Hash != interfaceRecord.FileHash {
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrConflict
	}
	document, err := configdoc.Parse(config.Body)
	if err != nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, err
	}
	analysis := document.Analysis()
	document.Destroy()
	var configured *configdoc.Peer
	for index := range analysis.Peers {
		if analysis.Peers[index].PublicKey == peer.PublicKey {
			configured = &analysis.Peers[index]
			break
		}
	}
	if configured == nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrConflict
	}
	material, err := s.repository.ClientMaterial(ctx, peer.ID)
	if err != nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, err
	}
	intent := peerUpdateIntent{
		PeerID: peer.ID, Name: peer.Name,
		ServerAllowedIPs: append([]string(nil), configured.AllowedIPs...),
		ClientRoutes:     append([]string(nil), material.Routes...), Endpoint: configured.Endpoint,
		PersistentKeepalive: configured.PersistentKeepalive,
	}
	if request.Name != nil {
		intent.Name = strings.TrimSpace(*request.Name)
		intent.UpdateName = intent.Name != peer.Name
	}
	if len(request.ServerAllowedIPs) > 0 {
		prefixes, err := validation.CanonicalPrefixes(request.ServerAllowedIPs)
		if err != nil {
			wipe(config.Body)
			return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		intent.ServerAllowedIPs = intent.ServerAllowedIPs[:0]
		for _, prefix := range prefixes {
			intent.ServerAllowedIPs = append(intent.ServerAllowedIPs, prefix.String())
		}
		intent.UpdateAllowedIPs = !samePrefixes(intent.ServerAllowedIPs, configured.AllowedIPs)
	}
	if len(request.ClientRoutes) > 0 {
		prefixes, err := validation.CanonicalPrefixes(request.ClientRoutes)
		if err != nil {
			wipe(config.Body)
			return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		intent.ClientRoutes = intent.ClientRoutes[:0]
		for _, prefix := range prefixes {
			intent.ClientRoutes = append(intent.ClientRoutes, prefix.String())
		}
		intent.UpdateClientRoutes = !samePrefixes(intent.ClientRoutes, material.Routes)
	}
	if request.Endpoint != nil {
		intent.Endpoint = strings.TrimSpace(*request.Endpoint)
		intent.UpdateEndpoint = intent.Endpoint != configured.Endpoint
	}
	if request.PersistentKeepalive != nil {
		intent.PersistentKeepalive = *request.PersistentKeepalive
		intent.UpdateKeepalive = intent.PersistentKeepalive != configured.PersistentKeepalive
	}
	if intent.Name == "" || len(intent.Name) > 128 || len(intent.ServerAllowedIPs) == 0 {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrInvalid
	}
	if !intent.UpdateName && !intent.UpdateAllowedIPs && !intent.UpdateClientRoutes &&
		!intent.UpdateEndpoint && !intent.UpdateKeepalive {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{},
			fmt.Errorf("%w: peer update contains no changes", ErrInvalid)
	}
	if err := validatePeerEndpoint(intent.Endpoint); err != nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	ownedRecords, err := s.repository.ActiveOwnedPrefixes(ctx, peer.InterfaceID)
	if err != nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, err
	}
	owned := make([]validation.OwnedPrefix, 0, len(ownedRecords))
	for _, item := range ownedRecords {
		prefix, parseErr := netip.ParsePrefix(item.CIDR)
		if parseErr == nil {
			owned = append(owned, validation.OwnedPrefix{PeerID: item.PeerID, Prefix: prefix})
		}
	}
	candidates, _ := validation.CanonicalPrefixes(intent.ServerAllowedIPs)
	if err := validation.RejectOverlaps(candidates, owned, peer.ID); err != nil {
		wipe(config.Body)
		return peerUpdateIntent{}, repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return intent, peer, interfaceRecord, config, nil
}

func validatePeerEndpoint(value string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, "\r\n\t /") {
		return errors.New("peer endpoint contains invalid characters")
	}
	hostValue, portValue, err := net.SplitHostPort(value)
	if err != nil || hostValue == "" {
		return errors.New("peer endpoint must be host:port")
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return errors.New("peer endpoint port is invalid")
	}
	return validation.EndpointHost(hostValue)
}

func (s *Service) rollbackPeerUpdate(
	ctx context.Context,
	operationID string,
	interfaceRecord repository.InterfaceRecord,
	peer repository.PeerRecord,
	psk []byte,
	snapshot *peerUpdateSnapshot,
	fileMayBeProposed bool,
) error {
	metadata, _ := s.repository.GetOperationMetadata(ctx, operationID)
	if metadata.State == agentoperation.StateExecuting || metadata.State == agentoperation.StateSnapshotted {
		_ = s.repository.TransitionOperation(
			ctx, operationID, metadata.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "PEER_UPDATE_FAILED", Message: "peer update operation failed"},
		)
	}
	var rollbackErrors []error
	if fileMayBeProposed {
		current, err := s.files.ReadConfig(interfaceRecord.Name)
		if err == nil {
			defer wipe(current.Body)
			if current.Hash == filesystem.SHA256(snapshot.Proposed) {
				_, err = s.files.ExchangeConfig(interfaceRecord.Name, current.Hash, snapshot.Original)
			} else if current.Hash != filesystem.SHA256(snapshot.Original) {
				err = filesystem.ErrRevisionConflict
			}
		}
		rollbackErrors = append(rollbackErrors, err)
	}
	if interfaceRecord.RuntimePresent {
		rollbackErrors = append(rollbackErrors, wgadapter.ApplyPeer(ctx, interfaceRecord.Name, wgadapter.PeerSpec{
			PublicKey: peer.PublicKey, PresharedKey: psk, AllowedIPs: peer.AllowedIPs,
			Endpoint: peer.Endpoint, PersistentKeepalive: uint16(peer.PersistentKeepalive),
		}))
	}
	if joined := errors.Join(rollbackErrors...); joined != nil {
		_ = s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateRollingBack, agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: "peer update rollback failed"},
		)
		return joined
	}
	return s.repository.FinishControlRollback(ctx, operationID)
}

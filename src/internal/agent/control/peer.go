// File: src/internal/agent/control/peer.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package control

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	wgadapter "github.com/wiregate-project/wiregate/internal/agent/adapters/wgctrl"
	"github.com/wiregate-project/wiregate/internal/agent/configdoc"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/profile"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/agent/validation"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerRequest struct {
	InterfaceID         string   `json:"interface_id"`
	Name                string   `json:"name"`
	KeyMode             string   `json:"key_mode"`
	ExternalPublicKey   string   `json:"external_public_key,omitempty"`
	ServerAllowedIPs    []string `json:"server_allowed_ips"`
	ClientRoutes        []string `json:"client_routes"`
	DNS                 []string `json:"dns"`
	MTU                 uint16   `json:"mtu,omitempty"`
	EndpointHost        string   `json:"endpoint_host"`
	EndpointPort        uint16   `json:"endpoint_port"`
	PersistentKeepalive uint16   `json:"persistent_keepalive"`
	UsePresharedKey     bool     `json:"use_preshared_key"`
}

type peerIntent struct {
	Request    PeerRequest                 `json:"request"`
	Allocation repository.AddressCandidate `json:"allocation"`
}

type peerSnapshot struct {
	Version      int        `json:"version"`
	Intent       peerIntent `json:"intent"`
	PublicKey    string     `json:"public_key"`
	PrivateKey   string     `json:"private_key,omitempty"`
	PresharedKey string     `json:"preshared_key,omitempty"`
	Original     []byte     `json:"original_config"`
	Proposed     []byte     `json:"proposed_config"`
}

type PeerResult struct {
	Result
	PeerID            string
	OneTimeArtifactID string
	OneTimeToken      []byte
}

func (s *Service) PreviewCreatePeer(
	ctx context.Context,
	request PeerRequest,
	expectedRevision int64,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor, "client:manage", false); err != nil {
		return Preview{}, err
	}
	request = normalizePeerRequest(request)
	interfaceRecord, config, allocation, err := s.preflightPeer(ctx, request, expectedRevision)
	if err != nil {
		return Preview{}, err
	}
	wipe(config.Body)
	request.ServerAllowedIPs = ensureTunnelAllowedIP(request.ServerAllowedIPs, allocation.Prefix)
	if len(request.ClientRoutes) == 0 {
		request.ClientRoutes = defaultClientRoutes(interfaceRecord)
	}
	intent := peerIntent{Request: request, Allocation: allocation}
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		return Preview{}, err
	}
	expected := expectedRevision
	expiresAt := s.now().Add(5 * time.Minute)
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		InterfaceID: request.InterfaceID, Type: "create_peer", IntentJSON: string(intentJSON),
		IdempotencyKey: actor.IdempotencyKey, ActorID: actor.ID, ActorRole: actor.Role,
		RequestID: actor.RequestID, Reason: actor.Reason, ExpectedRevision: &expected,
		OriginalFileHash:    interfaceRecord.FileHash,
		OriginalRuntimeHash: interfaceRecord.RuntimeFingerprint,
		ProposedDiffJSON:    `{"peer":{"before":null,"after":"active"}}`,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		if strings.Contains(err.Error(), "progress") || strings.Contains(err.Error(), "idempotency") {
			return Preview{}, fmt.Errorf("%w: %v", ErrConflict, err)
		}
		return Preview{}, err
	}
	diff, _ := json.Marshal(map[string]any{
		"interface_id": request.InterfaceID, "name": request.Name,
		"key_mode": request.KeyMode, "server_allowed_ips": request.ServerAllowedIPs,
		"client_routes": request.ClientRoutes, "endpoint_host": request.EndpointHost,
		"endpoint_port": request.EndpointPort, "preshared_key": request.UsePresharedKey,
	})
	return Preview{
		OperationID: operation.ID, OperationType: "create_peer",
		BaseRevision: expectedRevision, SemanticDiffJSON: string(diff),
		TextualDiffRedacted: fmt.Sprintf("add %s peer %s at %s", request.KeyMode, request.Name, allocation.Prefix),
		Disruptive:          false, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) CommitCreatePeer(
	ctx context.Context,
	operationID string,
	actor Actor,
) (PeerResult, error) {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return PeerResult{}, fmt.Errorf("%w: operation", ErrNotFound)
	}
	if metadata.Type != "create_peer" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || actor.Permission != "client:manage" {
		return PeerResult{}, ErrPermission
	}
	if metadata.State == agentoperation.StateCommitted {
		peer, getErr := s.repository.GetPeer(ctx, operationID)
		if getErr != nil {
			return PeerResult{}, getErr
		}
		return PeerResult{Result: Result{
			OperationID: operationID, State: metadata.State,
			InterfaceID: peer.InterfaceID,
		}, PeerID: peer.ID}, nil
	}
	if metadata.State != agentoperation.StatePending || metadata.ExpectedRevision == nil ||
		agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		return PeerResult{}, fmt.Errorf("%w: preview is no longer committable", ErrConflict)
	}
	var intent peerIntent
	if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil {
		return PeerResult{}, err
	}
	unlock, err := s.lockInterfaceByID(ctx, intent.Request.InterfaceID)
	if err != nil {
		return PeerResult{}, err
	}
	defer unlock()
	interfaceRecord, config, _, err := s.preflightPeer(ctx, intent.Request, *metadata.ExpectedRevision)
	if err != nil {
		return PeerResult{}, err
	}
	defer wipe(config.Body)
	if config.Hash != metadata.OriginalFileHash {
		return PeerResult{}, fmt.Errorf("%w: config changed after preview", ErrConflict)
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return PeerResult{}, fmt.Errorf("%w: operation state changed", ErrConflict)
	}
	return s.executeCreatePeer(ctx, operationID, interfaceRecord, config, intent)
}

func (s *Service) executeCreatePeer(
	ctx context.Context,
	operationID string,
	interfaceRecord repository.InterfaceRecord,
	config filesystem.ConfigFile,
	intent peerIntent,
) (PeerResult, error) {
	request := intent.Request
	var privateKey wgtypes.Key
	var publicKey string
	var privateText string
	var err error
	if request.KeyMode == "external" {
		publicKey = request.ExternalPublicKey
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			s.rejectValidated(ctx, operationID, "PEER_KEY_GENERATION_FAILED")
			return PeerResult{}, err
		}
		privateText = privateKey.String()
		publicKey = privateKey.PublicKey().String()
	}
	pskText := ""
	if request.UsePresharedKey {
		psk, err := wgtypes.GenerateKey()
		if err != nil {
			s.rejectValidated(ctx, operationID, "PEER_PSK_GENERATION_FAILED")
			return PeerResult{}, err
		}
		pskText = psk.String()
	}
	document, err := configdoc.Parse(config.Body)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_CONFIG_PARSE_FAILED")
		return PeerResult{}, err
	}
	defer document.Destroy()
	if err := document.AddPeer(configdoc.NewPeer{
		PublicKey: publicKey, PresharedKey: pskText,
		AllowedIPs:          request.ServerAllowedIPs,
		PersistentKeepalive: request.PersistentKeepalive,
	}); err != nil {
		s.rejectValidated(ctx, operationID, "PEER_CONFIG_PATCH_FAILED")
		return PeerResult{}, err
	}
	proposed := document.Bytes()
	defer wipe(proposed)
	snapshot := peerSnapshot{
		Version: 1, Intent: intent, PublicKey: publicKey,
		PrivateKey: privateText, PresharedKey: pskText,
		Original: config.Body, Proposed: proposed,
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_SNAPSHOT_FAILED")
		return PeerResult{}, err
	}
	defer wipe(payload)
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_SNAPSHOT_FAILED")
		return PeerResult{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{
		GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload",
	}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_SNAPSHOT_FAILED")
		return PeerResult{}, err
	}
	if err := s.repository.SnapshotOperation(
		ctx, operationID, secretContext, envelope,
		config.Hash, interfaceRecord.RuntimeFingerprint, nil,
	); err != nil {
		s.rejectValidated(ctx, operationID, "PEER_SNAPSHOT_FAILED")
		return PeerResult{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil,
	); err != nil {
		return PeerResult{}, err
	}
	active := interfaceRecord.RuntimePresent
	if active {
		if err := wgadapter.ApplyPeer(ctx, interfaceRecord.Name, wgadapter.PeerSpec{
			PublicKey: publicKey, PresharedKey: []byte(pskText),
			AllowedIPs:          request.ServerAllowedIPs,
			PersistentKeepalive: request.PersistentKeepalive,
		}); err != nil {
			return PeerResult{}, errors.Join(err, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, false))
		}
	}
	if _, err := s.files.ExchangeConfig(interfaceRecord.Name, config.Hash, proposed); err != nil {
		return PeerResult{}, errors.Join(err, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, false))
	}
	if active {
		state, err := host.InspectPeer(interfaceRecord.Name, publicKey)
		if err != nil || !state.Present || !samePrefixes(state.AllowedIPs, request.ServerAllowedIPs) {
			return PeerResult{}, errors.Join(errors.New("created peer verification failed"), err,
				s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
		}
	}
	proposedHash := filesystem.SHA256(proposed)
	device, _ := host.InspectDevice(interfaceRecord.Name)
	permanentPrivate, permanentPSK, err := s.sealPeerSecrets(master, operationID, privateText, pskText, request.KeyMode)
	if err != nil {
		return PeerResult{}, errors.Join(err, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
	}
	dnsJSON, _ := json.Marshal(request.DNS)
	input := repository.PeerCreateInput{
		ID: operationID, InterfaceID: interfaceRecord.ID, Name: request.Name,
		PublicKey: publicKey, KeyMode: request.KeyMode,
		AllowedIPs: request.ServerAllowedIPs, ClientRoutes: request.ClientRoutes,
		DNSJSON: string(dnsJSON), MTU: int(request.MTU), EndpointHost: request.EndpointHost,
		EndpointPort: int(request.EndpointPort), PersistentKeepalive: int(request.PersistentKeepalive),
		Allocation: intent.Allocation, ClientPrivate: permanentPrivate, PresharedKey: permanentPSK,
		OriginalFileHash: config.Hash, ProposedFileHash: proposedHash,
		RuntimeFingerprint: device.Fingerprint,
	}
	var token []byte
	if request.KeyMode == "one_time" {
		artifactID, idErr := ids.NewV7(s.now())
		if idErr != nil {
			return PeerResult{}, errors.Join(idErr, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
		}
		token = make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return PeerResult{}, errors.Join(err, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
		}
		clientConfig, renderErr := s.renderClientConfig(request, interfaceRecord, privateText, pskText, publicKey)
		if renderErr != nil {
			wipe(token)
			return PeerResult{}, errors.Join(renderErr, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
		}
		artifactContext := secret.Context{
			GatewayID: s.gatewayID, OwnerType: "artifact",
			OwnerID: artifactID, Purpose: "one_time_payload",
		}
		artifactEnvelope, sealErr := secret.Seal(master, s.keyVersion, artifactContext, clientConfig, nil)
		wipe(clientConfig)
		if sealErr != nil {
			wipe(token)
			return PeerResult{}, errors.Join(sealErr, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
		}
		input.OneTime = &repository.OneTimeInput{
			ID: artifactID, TokenHash: secret.TokenHash(token),
			ExpiresAt: s.now().Add(s.artifactTTL),
			Secret:    repository.SecretInput{Context: artifactContext, Envelope: artifactEnvelope},
		}
	}
	revision, err := s.repository.CompletePeerCreate(ctx, operationID, input)
	if err != nil {
		wipe(token)
		return PeerResult{}, errors.Join(err, s.rollbackPeerCreate(ctx, operationID, interfaceRecord, &snapshot, true))
	}
	if err := s.repository.FinalizeControlOperation(
		ctx, operationID, "create_peer", "peer", operationID,
		interfaceRecord.Revision, revision,
	); err != nil {
		// Host and metadata already agree. Recovery finalizes this verifying
		// operation; do not destroy a working peer because only audit commit failed.
		wipe(token)
		return PeerResult{}, err
	}
	result := PeerResult{
		Result: Result{OperationID: operationID, State: agentoperation.StateCommitted,
			InterfaceID: interfaceRecord.ID, InterfaceRevision: revision,
			EffectiveNextBoot: !active},
		PeerID: operationID,
	}
	if input.OneTime != nil {
		result.OneTimeArtifactID = input.OneTime.ID
		result.OneTimeToken = token
	}
	return result, nil
}

func (s *Service) preflightPeer(
	ctx context.Context,
	request PeerRequest,
	expectedRevision int64,
) (repository.InterfaceRecord, filesystem.ConfigFile, repository.AddressCandidate, error) {
	if request.InterfaceID == "" || request.Name == "" || len(request.Name) > 128 {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: interface and peer name are required", ErrInvalid)
	}
	if request.KeyMode != "managed" && request.KeyMode != "one_time" && request.KeyMode != "external" {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: invalid key mode", ErrInvalid)
	}
	if request.KeyMode == "external" {
		if err := validation.WireGuardKey(request.ExternalPublicKey); err != nil {
			return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: invalid external public key", ErrInvalid)
		}
	} else if request.ExternalPublicKey != "" {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: external public key is only valid in external mode", ErrInvalid)
	}
	if err := validation.EndpointHost(request.EndpointHost); err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validation.ListenPort(request.EndpointPort); err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validation.MTU(request.MTU); err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := validation.DNS(request.DNS); err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	interfaceRecord, err := s.repository.GetInterface(ctx, request.InterfaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, ErrNotFound
	}
	if err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, err
	}
	if interfaceRecord.ManagementMode != "managed" && interfaceRecord.ManagementMode != "adopted" {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: interface is read-only", ErrPrecondition)
	}
	if !interfaceRecord.ConfigPresent || interfaceRecord.DriftState != "none" ||
		interfaceRecord.Revision != expectedRevision {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: interface revision or drift changed", ErrConflict)
	}
	config, err := s.files.ReadConfig(interfaceRecord.Name)
	if err != nil || config.Hash != interfaceRecord.FileHash {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: authoritative config changed", ErrConflict)
	}
	allocation := repository.AddressCandidate{}
	if len(request.ServerAllowedIPs) == 0 {
		allocation, err = s.repository.NextAvailableAddress(ctx, request.InterfaceID)
	} else {
		allocation, err = s.repository.ValidateAddressCandidate(ctx, request.InterfaceID, request.ServerAllowedIPs[0])
	}
	if err != nil {
		wipe(config.Body)
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	candidates, err := validation.CanonicalPrefixes(ensureTunnelAllowedIP(request.ServerAllowedIPs, allocation.Prefix))
	if err != nil {
		wipe(config.Body)
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	existing, err := s.repository.ActiveOwnedPrefixes(ctx, request.InterfaceID)
	if err != nil {
		wipe(config.Body)
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, err
	}
	owned := make([]validation.OwnedPrefix, 0, len(existing))
	for _, value := range existing {
		prefix, parseErr := netip.ParsePrefix(value.CIDR)
		if parseErr == nil {
			owned = append(owned, validation.OwnedPrefix{PeerID: value.PeerID, Prefix: prefix})
		}
	}
	if err := validation.RejectOverlaps(candidates, owned, ""); err != nil {
		wipe(config.Body)
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, repository.AddressCandidate{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return interfaceRecord, config, allocation, nil
}

func (s *Service) sealPeerSecrets(
	master []byte,
	peerID, privateKey, psk, keyMode string,
) (*repository.SecretInput, *repository.SecretInput, error) {
	var privateInput, pskInput *repository.SecretInput
	if keyMode == "managed" {
		secretContext := secret.Context{
			GatewayID: s.gatewayID, OwnerType: "peer", OwnerID: peerID,
			Purpose: "client_private_key",
		}
		envelope, err := secret.Seal(master, s.keyVersion, secretContext, []byte(privateKey), nil)
		if err != nil {
			return nil, nil, err
		}
		privateInput = &repository.SecretInput{Context: secretContext, Envelope: envelope}
	}
	if psk != "" {
		fingerprintKey, err := s.fingerprintKey()
		if err != nil {
			return nil, nil, err
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(psk)
		if decodeErr != nil || len(decoded) != 32 {
			wipe(fingerprintKey)
			wipe(decoded)
			return nil, nil, errors.New("invalid generated preshared key")
		}
		fingerprint, err := secret.Fingerprint(fingerprintKey, decoded)
		wipe(fingerprintKey)
		wipe(decoded)
		if err != nil {
			return nil, nil, err
		}
		secretContext := secret.Context{
			GatewayID: s.gatewayID, OwnerType: "peer", OwnerID: peerID,
			Purpose: "preshared_key",
		}
		envelope, err := secret.Seal(master, s.keyVersion, secretContext, []byte(psk), fingerprint)
		if err != nil {
			return nil, nil, err
		}
		pskInput = &repository.SecretInput{Context: secretContext, Envelope: envelope}
	}
	return privateInput, pskInput, nil
}

func (s *Service) renderClientConfig(
	request PeerRequest,
	interfaceRecord repository.InterfaceRecord,
	privateKey, psk, _ string,
) ([]byte, error) {
	serverPublic := interfaceRecord.PublicKey
	if serverPublic == "" && interfaceRecord.RuntimePresent {
		device, err := host.InspectDevice(interfaceRecord.Name)
		if err != nil {
			return nil, err
		}
		serverPublic = device.PublicKey
	}
	return profile.RenderClientConfig(profile.ClientConfig{
		PrivateKey: []byte(privateKey), Addresses: []string{request.ServerAllowedIPs[0]},
		DNS: request.DNS, MTU: request.MTU, ServerPublicKey: serverPublic,
		PresharedKey: []byte(psk), EndpointHost: request.EndpointHost,
		EndpointPort: request.EndpointPort, Routes: request.ClientRoutes,
		PersistentKeepalive: request.PersistentKeepalive,
	})
}

func (s *Service) rollbackPeerCreate(
	ctx context.Context,
	operationID string,
	interfaceRecord repository.InterfaceRecord,
	snapshot *peerSnapshot,
	fileMayBeProposed bool,
) error {
	metadata, _ := s.repository.GetOperationMetadata(ctx, operationID)
	if metadata.State == agentoperation.StateExecuting || metadata.State == agentoperation.StateSnapshotted {
		if err := s.repository.TransitionOperation(
			ctx, operationID, metadata.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "CREATE_PEER_FAILED", Message: "peer creation failed"},
		); err != nil {
			return err
		}
	}
	var rollbackErrors []error
	if interfaceRecord.RuntimePresent {
		if state, err := host.InspectPeer(interfaceRecord.Name, snapshot.PublicKey); err == nil && state.Present {
			rollbackErrors = append(rollbackErrors, wgadapter.RemovePeer(ctx, interfaceRecord.Name, snapshot.PublicKey))
		}
	}
	if fileMayBeProposed {
		current, err := s.files.ReadConfig(interfaceRecord.Name)
		if err != nil {
			rollbackErrors = append(rollbackErrors, err)
		} else {
			defer wipe(current.Body)
			if current.Hash == filesystem.SHA256(snapshot.Proposed) {
				_, err = s.files.ExchangeConfig(interfaceRecord.Name, current.Hash, snapshot.Original)
				rollbackErrors = append(rollbackErrors, err)
			} else if current.Hash != filesystem.SHA256(snapshot.Original) {
				rollbackErrors = append(rollbackErrors, filesystem.ErrRevisionConflict)
			}
		}
	}
	if joined := errors.Join(rollbackErrors...); joined != nil {
		_ = s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateRollingBack, agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: "peer rollback failed"},
		)
		return joined
	}
	return s.repository.FinishControlRollback(ctx, operationID)
}

func (s *Service) lockInterfaceByID(ctx context.Context, interfaceID string) (func(), error) {
	record, err := s.repository.GetInterface(ctx, interfaceID)
	if err != nil {
		return nil, err
	}
	return s.lockInterface(record.Name)
}

func (s *Service) rejectValidated(ctx context.Context, operationID, code string) {
	_ = s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateValidated, agentoperation.StateRejected,
		&agentoperation.Failure{Code: code, Message: "peer operation preparation failed"},
	)
}

func normalizePeerRequest(request PeerRequest) PeerRequest {
	request.InterfaceID = strings.TrimSpace(request.InterfaceID)
	request.Name = strings.TrimSpace(request.Name)
	request.KeyMode = strings.TrimSpace(request.KeyMode)
	request.ExternalPublicKey = strings.TrimSpace(request.ExternalPublicKey)
	request.EndpointHost = strings.TrimSpace(request.EndpointHost)
	for index := range request.ServerAllowedIPs {
		request.ServerAllowedIPs[index] = strings.TrimSpace(request.ServerAllowedIPs[index])
	}
	for index := range request.ClientRoutes {
		request.ClientRoutes[index] = strings.TrimSpace(request.ClientRoutes[index])
	}
	if request.KeyMode == "" {
		request.KeyMode = "managed"
	}
	return request
}

func ensureTunnelAllowedIP(values []string, tunnel string) []string {
	result := append([]string(nil), values...)
	if !slices.Contains(result, tunnel) {
		result = append([]string{tunnel}, result...)
	}
	return result
}

func defaultClientRoutes(record repository.InterfaceRecord) []string {
	switch record.DeploymentProfile {
	case "full_tunnel":
		return []string{"0.0.0.0/0"}
	case "server_only":
		var result []string
		for _, address := range record.Addresses {
			bits := 128
			if address.Family == 4 {
				bits = 32
			}
			result = append(result, netip.PrefixFrom(netip.MustParseAddr(address.Address), bits).String())
		}
		return result
	default:
		return nil
	}
}

func samePrefixes(left, right []string) bool {
	a, errA := validation.CanonicalPrefixes(left)
	b, errB := validation.CanonicalPrefixes(right)
	return errA == nil && errB == nil && slices.Equal(a, b)
}

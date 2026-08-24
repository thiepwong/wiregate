package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	wgadapter "github.com/wiregate-project/wiregate/internal/agent/adapters/wgctrl"
	"github.com/wiregate-project/wiregate/internal/agent/configdoc"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

type lifecycleIntent struct {
	PeerID   string `json:"peer_id"`
	Mutation string `json:"mutation"`
}

type lifecycleSnapshot struct {
	Version  int             `json:"version"`
	Intent   lifecycleIntent `json:"intent"`
	Original []byte          `json:"original_config"`
	Proposed []byte          `json:"proposed_config"`
}

func (s *Service) PreviewPeerLifecycle(
	ctx context.Context,
	peerID, mutation string,
	expectedRevision int64,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor, "client:manage", false); err != nil {
		return Preview{}, err
	}
	mutation = strings.ToLower(strings.TrimSpace(mutation))
	peer, interfaceRecord, config, err := s.preflightPeerLifecycle(ctx, peerID, mutation, expectedRevision)
	if err != nil {
		return Preview{}, err
	}
	wipe(config.Body)
	intentJSON, _ := json.Marshal(lifecycleIntent{PeerID: peerID, Mutation: mutation})
	expected := expectedRevision
	expiresAt := s.now().Add(5 * time.Minute)
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		InterfaceID: interfaceRecord.ID, Type: mutation + "_peer", IntentJSON: string(intentJSON),
		IdempotencyKey: actor.IdempotencyKey, ActorID: actor.ID, ActorRole: actor.Role,
		RequestID: actor.RequestID, Reason: actor.Reason, ExpectedRevision: &expected,
		OriginalFileHash:    interfaceRecord.FileHash,
		OriginalRuntimeHash: interfaceRecord.RuntimeFingerprint,
		ProposedDiffJSON: fmt.Sprintf(`{"peer":{"id":%q,"before":%q,"after":%q}}`,
			peer.ID, peer.LifecycleState, lifecycleTarget(mutation)),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return Preview{
		OperationID: operation.ID, OperationType: mutation + "_peer",
		BaseRevision: expectedRevision,
		SemanticDiffJSON: fmt.Sprintf(`{"peer_id":%q,"lifecycle_state":{"before":%q,"after":%q}}`,
			peer.ID, peer.LifecycleState, lifecycleTarget(mutation)),
		TextualDiffRedacted: fmt.Sprintf("%s peer %s", mutation, peer.Name),
		Disruptive:          mutation == "revoke", ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) CommitPeerLifecycle(
	ctx context.Context,
	operationID, mutation string,
	actor Actor,
) (Result, error) {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return Result{}, ErrNotFound
	}
	mutation = strings.ToLower(strings.TrimSpace(mutation))
	if metadata.Type != mutation+"_peer" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || actor.Permission != "client:manage" {
		return Result{}, ErrPermission
	}
	if metadata.State == agentoperation.StateCommitted {
		return Result{OperationID: operationID, State: metadata.State,
			InterfaceID: metadata.InterfaceID}, nil
	}
	if metadata.State != agentoperation.StatePending || metadata.ExpectedRevision == nil ||
		agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		return Result{}, fmt.Errorf("%w: lifecycle preview expired", ErrConflict)
	}
	var intent lifecycleIntent
	if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil || intent.Mutation != mutation {
		return Result{}, fmt.Errorf("%w: invalid lifecycle intent", ErrInvalid)
	}
	peer, interfaceRecord, config, err := s.preflightPeerLifecycle(
		ctx, intent.PeerID, mutation, *metadata.ExpectedRevision,
	)
	if err != nil {
		return Result{}, err
	}
	defer wipe(config.Body)
	unlock, err := s.lockInterface(interfaceRecord.Name)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return Result{}, fmt.Errorf("%w: operation state changed", ErrConflict)
	}
	return s.executePeerLifecycle(ctx, operationID, mutation, peer, interfaceRecord, config)
}

func (s *Service) executePeerLifecycle(
	ctx context.Context,
	operationID, mutation string,
	peer repository.PeerRecord,
	interfaceRecord repository.InterfaceRecord,
	config filesystem.ConfigFile,
) (Result, error) {
	document, err := configdoc.Parse(config.Body)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_PARSE_FAILED")
		return Result{}, err
	}
	defer document.Destroy()
	material, materialErr := s.repository.ClientMaterial(ctx, peer.ID)
	if materialErr != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_SECRET_FAILED")
		return Result{}, materialErr
	}
	var psk []byte
	if material.PresharedKey != nil {
		psk, err = s.openPeerSecret(material.PresharedKey)
		if err != nil {
			s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_SECRET_FAILED")
			return Result{}, err
		}
		defer wipe(psk)
	}
	var archived []byte
	if mutation == "enable" {
		archivedSecret, loadErr := s.repository.ArchivedPeerBlock(ctx, peer.ID)
		if loadErr != nil {
			s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_ARCHIVE_FAILED")
			return Result{}, loadErr
		}
		archived, err = s.openPeerSecret(&archivedSecret)
		if err == nil {
			err = document.RestorePeerBlock(peer.PublicKey, archived)
		}
	} else {
		archived, err = document.RemovePeer(peer.PublicKey)
	}
	defer wipe(archived)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_PATCH_FAILED")
		return Result{}, err
	}
	proposed := document.Bytes()
	defer wipe(proposed)
	snapshot := lifecycleSnapshot{Version: 1,
		Intent:   lifecycleIntent{PeerID: peer.ID, Mutation: mutation},
		Original: config.Body, Proposed: proposed,
	}
	payload, _ := json.Marshal(snapshot)
	defer wipe(payload)
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload"}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	var archivedInput *repository.SecretInput
	if mutation != "enable" {
		archiveContext := secret.Context{
			GatewayID: s.gatewayID, OwnerType: "peer",
			OwnerID: peer.ID, Purpose: "archived_peer_block",
		}
		archiveEnvelope, sealErr := secret.Seal(
			master, s.keyVersion, archiveContext, archived, nil,
		)
		if sealErr != nil {
			s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_ARCHIVE_FAILED")
			return Result{}, sealErr
		}
		archivedInput = &repository.SecretInput{Context: archiveContext, Envelope: archiveEnvelope}
	}
	if err := s.repository.SnapshotOperation(ctx, operationID, secretContext, envelope,
		config.Hash, interfaceRecord.RuntimeFingerprint, nil); err != nil {
		s.rejectValidated(ctx, operationID, "PEER_LIFECYCLE_SNAPSHOT_FAILED")
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(ctx, operationID,
		agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil); err != nil {
		return Result{}, err
	}
	active := interfaceRecord.RuntimePresent
	if active {
		if mutation == "enable" {
			err = wgadapter.ApplyPeer(ctx, interfaceRecord.Name, wgadapter.PeerSpec{
				PublicKey: peer.PublicKey, PresharedKey: psk, AllowedIPs: peer.AllowedIPs,
				Endpoint: peer.Endpoint, PersistentKeepalive: uint16(peer.PersistentKeepalive),
			})
		} else {
			err = wgadapter.RemovePeer(ctx, interfaceRecord.Name, peer.PublicKey)
		}
		if err != nil {
			return Result{}, errors.Join(err, s.rollbackLifecycle(ctx, operationID, interfaceRecord, peer, psk, &snapshot, false))
		}
	}
	if _, err := s.files.ExchangeConfig(interfaceRecord.Name, config.Hash, proposed); err != nil {
		return Result{}, errors.Join(err, s.rollbackLifecycle(ctx, operationID, interfaceRecord, peer, psk, &snapshot, false))
	}
	if active {
		state, inspectErr := host.InspectPeer(interfaceRecord.Name, peer.PublicKey)
		shouldExist := mutation == "enable"
		if inspectErr != nil || state.Present != shouldExist ||
			(shouldExist && !samePrefixes(state.AllowedIPs, peer.AllowedIPs)) {
			return Result{}, errors.Join(errors.New("peer lifecycle verification failed"), inspectErr,
				s.rollbackLifecycle(ctx, operationID, interfaceRecord, peer, psk, &snapshot, true))
		}
	}
	device, _ := host.InspectDevice(interfaceRecord.Name)
	revision, err := s.repository.CompletePeerLifecycle(ctx, operationID, peer.ID, mutation,
		config.Hash, filesystem.SHA256(proposed), device.Fingerprint, archivedInput)
	if err != nil {
		return Result{}, errors.Join(err, s.rollbackLifecycle(ctx, operationID, interfaceRecord, peer, psk, &snapshot, true))
	}
	if err := s.repository.FinalizeControlOperation(ctx, operationID, mutation+"_peer", "peer", peer.ID,
		interfaceRecord.Revision, revision); err != nil {
		return Result{}, err
	}
	return Result{OperationID: operationID, State: agentoperation.StateCommitted,
		InterfaceID: interfaceRecord.ID, InterfaceRevision: revision,
		EffectiveNextBoot: !active}, nil
}

func (s *Service) preflightPeerLifecycle(
	ctx context.Context,
	peerID, mutation string,
	expectedRevision int64,
) (repository.PeerRecord, repository.InterfaceRecord, filesystem.ConfigFile, error) {
	if mutation != "disable" && mutation != "enable" && mutation != "revoke" {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{},
			fmt.Errorf("%w: invalid peer lifecycle mutation", ErrInvalid)
	}
	peer, err := s.repository.GetPeer(ctx, peerID)
	if err != nil {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrNotFound
	}
	if (mutation == "enable" && peer.LifecycleState != "disabled") ||
		(mutation != "enable" && peer.LifecycleState != "active") {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{},
			fmt.Errorf("%w: peer lifecycle state is incompatible", ErrPrecondition)
	}
	interfaceRecord, err := s.repository.GetInterface(ctx, peer.InterfaceID)
	if err != nil {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, err
	}
	if (interfaceRecord.ManagementMode != "managed" && interfaceRecord.ManagementMode != "adopted") ||
		interfaceRecord.Revision != expectedRevision || interfaceRecord.DriftState != "none" {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrConflict
	}
	config, err := s.files.ReadConfig(interfaceRecord.Name)
	if err != nil || config.Hash != interfaceRecord.FileHash {
		return repository.PeerRecord{}, repository.InterfaceRecord{}, filesystem.ConfigFile{}, ErrConflict
	}
	return peer, interfaceRecord, config, nil
}

func (s *Service) rollbackLifecycle(
	ctx context.Context,
	operationID string,
	interfaceRecord repository.InterfaceRecord,
	peer repository.PeerRecord,
	psk []byte,
	snapshot *lifecycleSnapshot,
	fileMayBeProposed bool,
) error {
	metadata, _ := s.repository.GetOperationMetadata(ctx, operationID)
	if metadata.State == agentoperation.StateExecuting || metadata.State == agentoperation.StateSnapshotted {
		_ = s.repository.TransitionOperation(ctx, operationID, metadata.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "PEER_LIFECYCLE_FAILED", Message: "peer lifecycle operation failed"})
	}
	var rollbackErrors []error
	if fileMayBeProposed {
		current, err := s.files.ReadConfig(interfaceRecord.Name)
		if err == nil {
			defer wipe(current.Body)
			if current.Hash == filesystem.SHA256(snapshot.Proposed) {
				_, err = s.files.ExchangeConfig(interfaceRecord.Name, current.Hash, snapshot.Original)
			}
		}
		rollbackErrors = append(rollbackErrors, err)
	}
	if interfaceRecord.RuntimePresent {
		if snapshot.Intent.Mutation == "enable" {
			rollbackErrors = append(rollbackErrors, wgadapter.RemovePeer(ctx, interfaceRecord.Name, peer.PublicKey))
		} else {
			rollbackErrors = append(rollbackErrors, wgadapter.ApplyPeer(ctx, interfaceRecord.Name, wgadapter.PeerSpec{
				PublicKey: peer.PublicKey, PresharedKey: psk, AllowedIPs: peer.AllowedIPs,
				Endpoint: peer.Endpoint, PersistentKeepalive: uint16(peer.PersistentKeepalive),
			}))
		}
	}
	if joined := errors.Join(rollbackErrors...); joined != nil {
		_ = s.repository.TransitionOperation(ctx, operationID, agentoperation.StateRollingBack,
			agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: "peer lifecycle rollback failed"})
		return joined
	}
	return s.repository.FinishControlRollback(ctx, operationID)
}

func lifecycleTarget(mutation string) string {
	if mutation == "enable" {
		return "active"
	}
	if mutation == "revoke" {
		return "revoked"
	}
	return "disabled"
}

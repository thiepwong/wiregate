// File: src/internal/agent/control/interface_state.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-09-09
// Description: Journal and apply destructive state changes for managed interfaces.

package control

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

const removedInterfaceState = "removed"

type interfaceStateIntent struct {
	InterfaceID  string `json:"interface_id"`
	DesiredState string `json:"desired_state"`
}

type removalFileSnapshot struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Body []byte `json:"body"`
}

type interfaceRemovalSnapshot struct {
	Version               int                   `json:"version"`
	Intent                interfaceStateIntent  `json:"intent"`
	Name                  string                `json:"name"`
	Files                 []removalFileSnapshot `json:"files"`
	WasActive             bool                  `json:"was_active"`
	WasEnabled            bool                  `json:"was_enabled"`
	CurrentIPv4Forwarding string                `json:"current_ipv4_forwarding,omitempty"`
	RestoreIPv4Forwarding string                `json:"restore_ipv4_forwarding,omitempty"`
}

func (s *Service) PreviewSetInterfaceState(
	ctx context.Context,
	interfaceID, desiredState string,
	expectedRevision int64,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor, "interface:manage", true); err != nil {
		return Preview{}, err
	}
	desiredState = strings.ToLower(strings.TrimSpace(desiredState))
	if desiredState != removedInterfaceState {
		return Preview{}, fmt.Errorf("%w: unsupported interface state", ErrInvalid)
	}
	record, err := s.preflightManagedRemoval(ctx, interfaceID, expectedRevision)
	if err != nil {
		return Preview{}, err
	}
	intent := interfaceStateIntent{InterfaceID: record.ID, DesiredState: desiredState}
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		return Preview{}, err
	}
	expiresAt := s.now().Add(5 * time.Minute)
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		InterfaceID: record.ID, Type: "set_interface_state", IntentJSON: string(intentJSON),
		IdempotencyKey: actor.IdempotencyKey, ActorID: actor.ID, ActorRole: actor.Role,
		RequestID: actor.RequestID, Reason: actor.Reason, ExpectedRevision: &expectedRevision,
		OriginalFileHash: record.FileHash, OriginalRuntimeHash: record.RuntimeFingerprint,
		ProposedDiffJSON: `{"interface":{"before":"managed","after":null}}`,
		ExpiresAt:        expiresAt,
		Steps: []agentoperation.StepRecord{
			{Name: "stop and disable WireGuard service", Kind: "systemd", OriginalFingerprint: "managed", ProposedFingerprint: "absent"},
			{Name: "remove owned host files", Kind: "file", OriginalFingerprint: record.FileHash, ProposedFingerprint: "absent"},
			{Name: "remove interface metadata", Kind: "database", OriginalFingerprint: fmt.Sprint(record.Revision), ProposedFingerprint: "absent"},
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "already") {
			return Preview{}, fmt.Errorf("%w: operation already in progress", ErrConflict)
		}
		return Preview{}, err
	}
	return Preview{
		OperationID: operation.ID, OperationType: "set_interface_state",
		BaseRevision: expectedRevision,
		SemanticDiffJSON: fmt.Sprintf(
			`{"interface_id":%q,"name":%q,"management_mode":{"before":"managed","after":null},"peer_count":%d}`,
			record.ID, record.Name, record.PeerCount,
		),
		TextualDiffRedacted: fmt.Sprintf(
			"permanently remove managed interface %s and %d peer(s); stop its tunnel; delete only WireGate-owned host files",
			record.Name, record.PeerCount,
		),
		Issues: []Issue{{
			Code: "MANAGED_INTERFACE_REMOVAL", Severity: "warning", Field: "desired_state",
			Summary:     "This permanently removes the managed interface, its peers, profiles, and WireGate-owned host resources.",
			Remediation: "Export any client profiles and confirm this SSH session does not depend on the tunnel.",
		}},
		Disruptive: true, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) CommitSetInterfaceState(
	ctx context.Context,
	operationID string,
	actor Actor,
) (Result, error) {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return Result{}, fmt.Errorf("%w: operation", ErrNotFound)
	}
	if metadata.Type != "set_interface_state" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || actor.Permission != "interface:manage" {
		return Result{}, ErrPermission
	}
	var intent interfaceStateIntent
	if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil ||
		intent.InterfaceID == "" || intent.DesiredState != removedInterfaceState {
		return Result{}, fmt.Errorf("%w: invalid interface-state intent", ErrInvalid)
	}
	if metadata.State == agentoperation.StateCommitted {
		revision := int64(0)
		if metadata.ExpectedRevision != nil {
			revision = *metadata.ExpectedRevision
		}
		return Result{OperationID: operationID, State: metadata.State,
			InterfaceID: intent.InterfaceID, InterfaceRevision: revision}, nil
	}
	if metadata.State != agentoperation.StatePending || metadata.ExpectedRevision == nil ||
		agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		return Result{}, fmt.Errorf("%w: preview is no longer committable", ErrConflict)
	}

	unlock, err := s.lockInterfaceName(ctx, intent.InterfaceID)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	record, err := s.preflightManagedRemoval(ctx, intent.InterfaceID, *metadata.ExpectedRevision)
	if err != nil {
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return Result{}, fmt.Errorf("%w: operation state changed", ErrConflict)
	}
	snapshot, err := s.buildInterfaceRemovalSnapshot(ctx, record, intent)
	if err != nil {
		s.rejectValidated(ctx, operationID, "INTERFACE_REMOVAL_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipeInterfaceRemovalSnapshot(&snapshot)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		s.rejectValidated(ctx, operationID, "INTERFACE_REMOVAL_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipe(payload)
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectValidated(ctx, operationID, "INTERFACE_REMOVAL_SNAPSHOT_FAILED")
		return Result{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload"}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		s.rejectValidated(ctx, operationID, "INTERFACE_REMOVAL_SNAPSHOT_FAILED")
		return Result{}, err
	}
	if err := s.repository.SnapshotOperation(
		ctx, operationID, secretContext, envelope, record.FileHash,
		record.RuntimeFingerprint, nil,
	); err != nil {
		s.rejectValidated(ctx, operationID, "INTERFACE_REMOVAL_SNAPSHOT_FAILED")
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil,
	); err != nil {
		return Result{}, errors.Join(err, s.rollbackInterfaceRemoval(ctx, operationID, &snapshot))
	}
	if err := s.removeManagedInterfaceHost(ctx, record, &snapshot); err != nil {
		return Result{}, errors.Join(err, s.rollbackInterfaceRemoval(ctx, operationID, &snapshot))
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateExecuting, agentoperation.StateVerifying, nil,
	); err != nil {
		return Result{}, errors.Join(err, s.rollbackInterfaceRemoval(ctx, operationID, &snapshot))
	}
	if _, _, err := s.repository.FinalizeManagedInterfaceRemoval(ctx, operationID); err != nil {
		return Result{}, errors.Join(err, s.rollbackInterfaceRemoval(ctx, operationID, &snapshot))
	}
	return Result{
		OperationID: operationID, State: agentoperation.StateCommitted,
		InterfaceID: intent.InterfaceID, InterfaceRevision: record.Revision,
	}, nil
}

func (s *Service) recoverInterfaceRemoval(
	ctx context.Context,
	metadata repository.OperationMetadata,
) error {
	secretContext, envelope, err := s.repository.LoadOperationSnapshot(ctx, metadata.ID)
	if err != nil {
		return err
	}
	master, err := s.masterKey(envelope.KeyVersion)
	if err != nil {
		return err
	}
	defer wipe(master)
	payload, err := secret.Open(master, secretContext, envelope)
	if err != nil {
		return err
	}
	defer wipe(payload)
	return s.recoverSnapshotted(ctx, metadata, payload)
}

func (s *Service) preflightManagedRemoval(
	ctx context.Context,
	interfaceID string,
	expectedRevision int64,
) (repository.InterfaceRecord, error) {
	record, err := s.repository.GetInterface(ctx, strings.TrimSpace(interfaceID))
	if errors.Is(err, sql.ErrNoRows) {
		return repository.InterfaceRecord{}, fmt.Errorf("%w: interface", ErrNotFound)
	}
	if err != nil {
		return repository.InterfaceRecord{}, err
	}
	if record.ManagementMode != "managed" {
		return repository.InterfaceRecord{}, fmt.Errorf(
			"%w: only interfaces created by WireGate can be removed", ErrPrecondition,
		)
	}
	if record.Revision != expectedRevision {
		return repository.InterfaceRecord{}, ErrConflict
	}
	if record.DriftState != "none" || !record.ConfigPresent {
		return repository.InterfaceRecord{}, fmt.Errorf(
			"%w: resolve interface drift before removal", ErrPrecondition,
		)
	}
	if err := host.RequireNativeTools(record.FirewallMode == "managed_nft"); err != nil {
		return repository.InterfaceRecord{}, fmt.Errorf("%w: %v", ErrPrecondition, err)
	}
	if !s.allowed(record.Name) || record.ConfigPath != filepath.Join(s.configRoot, record.Name+".conf") {
		return repository.InterfaceRecord{}, fmt.Errorf("%w: interface ownership is invalid", ErrPrecondition)
	}
	config, err := s.files.ReadConfig(record.Name)
	defer wipe(config.Body)
	if err != nil || config.Hash != record.FileHash ||
		!bytes.Contains(config.Body, []byte("WireGate-Operation: "+record.ID)) {
		return repository.InterfaceRecord{}, fmt.Errorf(
			"%w: managed configuration ownership or hash changed", ErrConflict,
		)
	}
	device, err := host.InspectDevice(record.Name)
	if err != nil {
		return repository.InterfaceRecord{}, err
	}
	active := host.ServiceActive(ctx, record.Name)
	if device.Present != active || device.Present != record.RuntimePresent ||
		(device.Present && device.Fingerprint != record.RuntimeFingerprint) {
		return repository.InterfaceRecord{}, fmt.Errorf(
			"%w: managed runtime changed before removal", ErrConflict,
		)
	}
	return record, nil
}

func (s *Service) lockInterfaceName(ctx context.Context, interfaceID string) (func(), error) {
	record, err := s.repository.GetInterface(ctx, strings.TrimSpace(interfaceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: interface", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return s.lockInterface(record.Name)
}

func (s *Service) buildInterfaceRemovalSnapshot(
	ctx context.Context,
	record repository.InterfaceRecord,
	intent interfaceStateIntent,
) (interfaceRemovalSnapshot, error) {
	resources, err := s.repository.ListManagedResources(ctx, record.ID)
	if err != nil {
		return interfaceRemovalSnapshot{}, err
	}
	snapshot := interfaceRemovalSnapshot{
		Version: 1, Intent: intent, Name: record.Name,
		WasActive:  host.ServiceActive(ctx, record.Name),
		WasEnabled: host.ServiceEnabled(ctx, record.Name),
	}
	marker := []byte("WireGate-Operation: " + record.ID)
	foundConfig := false
	for _, resource := range resources {
		if resource.Kind == "systemd_enable" {
			continue
		}
		if !s.validManagedResourcePath(record, resource) {
			return interfaceRemovalSnapshot{}, fmt.Errorf(
				"%w: invalid managed resource path", ErrPrecondition,
			)
		}
		info, err := os.Lstat(resource.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() > 4<<20 {
			return interfaceRemovalSnapshot{}, fmt.Errorf(
				"%w: managed resource is missing or unsafe", ErrPrecondition,
			)
		}
		body, err := os.ReadFile(resource.Path)
		if err != nil || !bytes.Contains(body, marker) {
			wipe(body)
			return interfaceRemovalSnapshot{}, fmt.Errorf(
				"%w: managed resource ownership changed", ErrConflict,
			)
		}
		snapshot.Files = append(snapshot.Files, removalFileSnapshot{
			Kind: resource.Kind, Path: resource.Path,
			Mode: uint32(info.Mode().Perm()), Body: body,
		})
		foundConfig = foundConfig || resource.Kind == "wireguard_config"
	}
	if !foundConfig {
		wipeInterfaceRemovalSnapshot(&snapshot)
		return interfaceRemovalSnapshot{}, fmt.Errorf(
			"%w: managed WireGuard configuration ownership is missing", ErrPrecondition,
		)
	}
	if record.DeploymentProfile != "server_only" {
		snapshot.CurrentIPv4Forwarding, err = host.ReadSysctlIPv4Forwarding()
		if err != nil {
			wipeInterfaceRemovalSnapshot(&snapshot)
			return interfaceRemovalSnapshot{}, err
		}
		snapshot.RestoreIPv4Forwarding, err = s.originalIPv4Forwarding(ctx, record.ID)
		if err != nil {
			wipeInterfaceRemovalSnapshot(&snapshot)
			return interfaceRemovalSnapshot{}, err
		}
		interfaces, listErr := s.repository.ListInterfaces(ctx)
		if listErr != nil {
			wipeInterfaceRemovalSnapshot(&snapshot)
			return interfaceRemovalSnapshot{}, listErr
		}
		for _, other := range interfaces {
			if other.ID != record.ID && other.ManagementMode == "managed" &&
				other.DeploymentProfile != "server_only" {
				snapshot.RestoreIPv4Forwarding = snapshot.CurrentIPv4Forwarding
				break
			}
		}
	}
	return snapshot, nil
}

func (s *Service) originalIPv4Forwarding(ctx context.Context, createOperationID string) (string, error) {
	secretContext, envelope, err := s.repository.LoadOperationSnapshot(ctx, createOperationID)
	if err != nil {
		return "", fmt.Errorf("load managed-interface creation snapshot: %w", err)
	}
	master, err := s.masterKey(envelope.KeyVersion)
	if err != nil {
		return "", err
	}
	defer wipe(master)
	payload, err := secret.Open(master, secretContext, envelope)
	if err != nil {
		return "", err
	}
	defer wipe(payload)
	var snapshot interfaceSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return "", err
	}
	if snapshot.OriginalIPv4Forwarding == "" {
		return "", errors.New("managed-interface forwarding snapshot is incomplete")
	}
	return snapshot.OriginalIPv4Forwarding, nil
}

func (s *Service) validManagedResourcePath(
	record repository.InterfaceRecord,
	resource repository.ManagedResourceRecord,
) bool {
	switch resource.Kind {
	case "wireguard_config":
		return resource.Path == filepath.Join(s.configRoot, record.Name+".conf") &&
			resource.Path == record.ConfigPath
	case "nft_up":
		return resource.Path == filepath.Join(s.networkRoot, record.Name, "up.nft")
	case "nft_down":
		return resource.Path == filepath.Join(s.networkRoot, record.Name, "down.nft")
	case "sysctl":
		return resource.Path == filepath.Join(s.sysctlRoot, "90-wiregate-"+record.Name+".conf")
	default:
		return false
	}
}

func (s *Service) removeManagedInterfaceHost(
	ctx context.Context,
	record repository.InterfaceRecord,
	snapshot *interfaceRemovalSnapshot,
) error {
	if snapshot.WasActive {
		if err := host.StopService(ctx, record.Name); err != nil {
			return err
		}
	}
	if snapshot.WasEnabled {
		if err := host.DisableService(ctx, record.Name); err != nil {
			return err
		}
	}
	marker := "WireGate-Operation: " + record.ID
	for _, file := range snapshot.Files {
		if err := host.RemoveOwnedFile(file.Path, marker); err != nil {
			return err
		}
	}
	if snapshot.RestoreIPv4Forwarding != "" {
		if err := host.SetSysctlIPv4Forwarding(snapshot.RestoreIPv4Forwarding); err != nil {
			return err
		}
	}
	device, err := host.InspectDevice(record.Name)
	if err != nil {
		return err
	}
	if device.Present {
		return errors.New("WireGuard device remains after managed interface removal")
	}
	for _, file := range snapshot.Files {
		if _, err := os.Lstat(file.Path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("managed host file remains after interface removal")
		}
	}
	return nil
}

func (s *Service) rollbackInterfaceRemoval(
	ctx context.Context,
	operationID string,
	snapshot *interfaceRemovalSnapshot,
) error {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return err
	}
	switch metadata.State {
	case agentoperation.StateSnapshotted, agentoperation.StateExecuting, agentoperation.StateVerifying:
		if err := s.repository.TransitionOperation(
			ctx, operationID, metadata.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "INTERFACE_REMOVAL_FAILED", Message: "managed interface removal failed"},
		); err != nil {
			return err
		}
	case agentoperation.StateRollingBack:
	case agentoperation.StateCommitted, agentoperation.StateRolledBack:
		return nil
	default:
		return errors.New("interface-removal operation cannot be rolled back from its current state")
	}
	var rollbackErrors []error
	for _, file := range snapshot.Files {
		info, statErr := os.Lstat(file.Path)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			rollbackErrors = append(rollbackErrors,
				host.WriteOwnedFile(file.Path, file.Body, os.FileMode(file.Mode), 0o700),
			)
		case statErr != nil:
			rollbackErrors = append(rollbackErrors, statErr)
		case !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0:
			rollbackErrors = append(rollbackErrors, errors.New("cannot restore over unsafe managed resource"))
		default:
			body, readErr := os.ReadFile(file.Path)
			if readErr != nil || !bytes.Equal(body, file.Body) {
				rollbackErrors = append(rollbackErrors, errors.New("managed resource changed during rollback"))
			}
			wipe(body)
		}
	}
	if snapshot.CurrentIPv4Forwarding != "" {
		rollbackErrors = append(rollbackErrors,
			host.SetSysctlIPv4Forwarding(snapshot.CurrentIPv4Forwarding),
		)
	}
	if snapshot.WasEnabled && !host.ServiceEnabled(ctx, snapshot.Name) {
		rollbackErrors = append(rollbackErrors, host.EnableService(ctx, snapshot.Name))
	}
	if snapshot.WasActive && !host.ServiceActive(ctx, snapshot.Name) {
		rollbackErrors = append(rollbackErrors, host.StartService(ctx, snapshot.Name))
	}
	if joined := errors.Join(rollbackErrors...); joined != nil {
		_ = s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateRollingBack, agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: "managed interface restoration failed"},
		)
		return joined
	}
	return s.repository.FinishControlRollback(ctx, operationID)
}

func wipeInterfaceRemovalSnapshot(snapshot *interfaceRemovalSnapshot) {
	for index := range snapshot.Files {
		wipe(snapshot.Files[index].Body)
	}
}

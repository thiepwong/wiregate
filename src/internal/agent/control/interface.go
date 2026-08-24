// File: src/internal/agent/control/interface.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/adapters/host"
	"github.com/wiregate-project/wiregate/internal/agent/network"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/profile"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/agent/validation"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	ErrPermission   = errors.New("control permission denied")
	ErrConflict     = errors.New("control revision conflict")
	ErrInvalid      = errors.New("control validation failed")
	ErrPrecondition = errors.New("control precondition failed")
	ErrNotFound     = errors.New("control resource not found")
)

type Actor struct {
	ID             string
	Role           string
	RequestID      string
	Permission     string
	IdempotencyKey string
	Reason         string
}

type InterfaceRequest struct {
	Name              string   `json:"name"`
	Addresses         []string `json:"addresses"`
	ListenPort        uint16   `json:"listen_port"`
	DeploymentProfile string   `json:"deployment_profile"`
	FirewallMode      string   `json:"firewall_mode"`
	LANCIDRs          []string `json:"lan_cidrs"`
	EgressDevice      string   `json:"egress_device"`
	AutoStart         bool     `json:"auto_start"`
}

type Preview struct {
	OperationID         string
	OperationType       string
	BaseRevision        int64
	SemanticDiffJSON    string
	TextualDiffRedacted string
	Issues              []Issue
	Disruptive          bool
	ExpiresAt           time.Time
}

type Issue struct {
	Code        string
	Severity    string
	Field       string
	Summary     string
	Remediation string
}

type Result struct {
	OperationID       string
	State             agentoperation.State
	InterfaceID       string
	InterfaceRevision int64
	EffectiveNextBoot bool
}

type interfaceSnapshot struct {
	Version                int              `json:"version"`
	Request                InterfaceRequest `json:"request"`
	PrivateKey             string           `json:"private_key"`
	Config                 []byte           `json:"config"`
	OriginalIPv4Forwarding string           `json:"original_ipv4_forwarding,omitempty"`
}

type Service struct {
	repository     *repository.Repository
	files          *filesystem.Store
	masterKey      func(uint32) ([]byte, error)
	fingerprintKey func() ([]byte, error)
	gatewayID      string
	keyVersion     uint32
	artifactTTL    time.Duration
	configRoot     string
	networkRoot    string
	sysctlRoot     string
	allowed        func(string) bool
	now            func() time.Time
	localLocksMu   sync.Mutex
	localLocks     map[string]*sync.Mutex
}

func New(
	repository *repository.Repository,
	files *filesystem.Store,
	masterKey func(uint32) ([]byte, error),
	fingerprintKey func() ([]byte, error),
	gatewayID string,
	keyVersion uint32,
	artifactTTL time.Duration,
	configRoot string,
	allowed func(string) bool,
) (*Service, error) {
	if repository == nil || files == nil || masterKey == nil || fingerprintKey == nil || gatewayID == "" ||
		keyVersion == 0 || artifactTTL <= 0 || configRoot == "" || allowed == nil {
		return nil, errors.New("control service dependencies are required")
	}
	return &Service{
		repository: repository, files: files, masterKey: masterKey,
		fingerprintKey: fingerprintKey, gatewayID: gatewayID,
		keyVersion: keyVersion, artifactTTL: artifactTTL, configRoot: configRoot,
		networkRoot: "/etc/wiregate/network", sysctlRoot: "/etc/sysctl.d",
		allowed: allowed, now: func() time.Time { return time.Now().UTC() },
		localLocks: make(map[string]*sync.Mutex),
	}, nil
}

func (s *Service) PreviewCreateInterface(
	ctx context.Context,
	request InterfaceRequest,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor, "interface:create", true); err != nil {
		return Preview{}, err
	}
	request = normalizeInterfaceRequest(request)
	issues, err := s.preflightCreate(ctx, request)
	if err != nil {
		return Preview{}, err
	}
	intent, err := json.Marshal(request)
	if err != nil {
		return Preview{}, err
	}
	expiresAt := s.now().Add(5 * time.Minute)
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		Type: "create_interface", IntentJSON: string(intent),
		IdempotencyKey: actor.IdempotencyKey, ActorID: actor.ID,
		ActorRole: actor.Role, RequestID: actor.RequestID, Reason: actor.Reason,
		ProposedDiffJSON: `{"interface":{"before":null,"after":"managed"}}`,
		ExpiresAt:        expiresAt,
	})
	if err != nil {
		if strings.Contains(err.Error(), "already") {
			return Preview{}, fmt.Errorf("%w: operation already in progress", ErrConflict)
		}
		return Preview{}, err
	}
	plan, err := buildNetworkPlan(operation.ID, request)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	diff, _ := json.Marshal(map[string]any{
		"name": request.Name, "addresses": request.Addresses,
		"listen_port": request.ListenPort, "deployment_profile": request.DeploymentProfile,
		"firewall_mode": request.FirewallMode, "auto_start": request.AutoStart,
		"client_routes": plan.ClientRoutes, "nft_table": plan.TableName,
		"external_firewall_checklist": plan.ExternalChecklist,
	})
	return Preview{
		OperationID: operation.ID, OperationType: "create_interface",
		SemanticDiffJSON: string(diff),
		TextualDiffRedacted: fmt.Sprintf(
			"create %s at %s; listen UDP %d; profile=%s; firewall=%s",
			request.Name, strings.Join(request.Addresses, ","), request.ListenPort,
			request.DeploymentProfile, request.FirewallMode,
		),
		Issues: issues, Disruptive: false, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) CommitCreateInterface(
	ctx context.Context,
	operationID string,
	actor Actor,
) (Result, error) {
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return Result{}, fmt.Errorf("%w: operation", ErrNotFound)
	}
	if metadata.Type != "create_interface" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || actor.Permission != "interface:create" {
		return Result{}, ErrPermission
	}
	if metadata.State == agentoperation.StateCommitted {
		record, getErr := s.repository.GetInterface(ctx, operationID)
		if getErr != nil {
			return Result{}, getErr
		}
		return Result{OperationID: operationID, State: metadata.State,
			InterfaceID: record.ID, InterfaceRevision: record.Revision}, nil
	}
	if metadata.State != agentoperation.StatePending ||
		agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		return Result{}, fmt.Errorf("%w: preview is no longer committable", ErrConflict)
	}
	var request InterfaceRequest
	if err := json.Unmarshal([]byte(metadata.IntentJSON), &request); err != nil {
		return Result{}, err
	}
	request = normalizeInterfaceRequest(request)
	unlock, err := s.lockInterface(request.Name)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if _, err := s.preflightCreate(ctx, request); err != nil {
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return Result{}, fmt.Errorf("%w: operation state changed", ErrConflict)
	}
	configPath := filepath.Join(s.configRoot, request.Name+".conf")
	reservation := repository.ManagedInterfaceInput{
		ID: operationID, Name: request.Name, ConfigPath: configPath,
		ListenPort: int(request.ListenPort), DeploymentProfile: request.DeploymentProfile,
		FirewallMode: request.FirewallMode, AutoStart: request.AutoStart,
	}
	if err := s.repository.ReserveManagedInterface(ctx, operationID, reservation); err != nil {
		_ = s.repository.RejectManagedInterfaceReservation(ctx, operationID, &agentoperation.Failure{
			Code: "INTERFACE_RESERVATION_FAILED", Message: "interface reservation failed",
		})
		return Result{}, fmt.Errorf("%w: interface name changed", ErrConflict)
	}
	result, err := s.executeCreateInterface(ctx, operationID, request, reservation)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (s *Service) executeCreateInterface(
	ctx context.Context,
	operationID string,
	request InterfaceRequest,
	reservation repository.ManagedInterfaceInput,
) (Result, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	privateText := privateKey.String()
	defer wipe([]byte(privateText))
	plan, err := buildNetworkPlan(operationID, request)
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	configBody, err := profile.RenderServerConfig(profile.ServerConfig{
		OperationID: operationID, PrivateKey: []byte(privateText),
		Addresses: request.Addresses, ListenPort: request.ListenPort,
		PostUp: plan.PostUp, PostDown: plan.PostDown,
	})
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	defer wipe(configBody)
	originalForwarding := ""
	if len(plan.Sysctl) > 0 {
		originalForwarding, err = host.ReadSysctlIPv4Forwarding()
		if err != nil {
			s.rejectReservation(ctx, operationID)
			return Result{}, err
		}
	}
	payload, err := json.Marshal(interfaceSnapshot{
		Version: 1, Request: request, PrivateKey: privateText,
		Config: configBody, OriginalIPv4Forwarding: originalForwarding,
	})
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	defer wipe(payload)
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{
		GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload",
	}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	if err := s.repository.SnapshotOperation(
		ctx, operationID, secretContext, envelope, "", "", nil,
	); err != nil {
		s.rejectReservation(ctx, operationID)
		return Result{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil,
	); err != nil {
		return Result{}, err
	}
	if err := s.applyInterfaceHost(ctx, operationID, request, plan, configBody); err != nil {
		rollbackErr := s.rollbackCreateInterface(ctx, operationID, &interfaceSnapshot{
			Request: request, Config: configBody, OriginalIPv4Forwarding: originalForwarding,
		})
		return Result{}, errors.Join(err, rollbackErr)
	}
	device, err := host.InspectDevice(request.Name)
	if err != nil || !device.Present || device.ListenPort != int(request.ListenPort) ||
		device.PublicKey != privateKey.PublicKey().String() {
		rollbackErr := s.rollbackCreateInterface(ctx, operationID, &interfaceSnapshot{
			Request: request, Config: configBody, OriginalIPv4Forwarding: originalForwarding,
		})
		return Result{}, errors.Join(errors.New("created WireGuard device verification failed"), err, rollbackErr)
	}
	fileHash, err := host.FileSHA256(reservation.ConfigPath)
	if err != nil {
		return Result{}, errors.Join(err, s.rollbackCreateInterface(ctx, operationID, &interfaceSnapshot{
			Request: request, Config: configBody, OriginalIPv4Forwarding: originalForwarding,
		}))
	}
	reservation.PublicKey = device.PublicKey
	reservation.Addresses = request.Addresses
	reservation.FileHash = fileHash
	reservation.RuntimeFingerprint = device.Fingerprint
	resources := s.interfaceResources(operationID, request, plan, fileHash)
	revision, err := s.repository.CompleteManagedInterface(ctx, operationID, reservation, resources)
	if err != nil {
		return Result{}, errors.Join(err, s.rollbackCreateInterface(ctx, operationID, &interfaceSnapshot{
			Request: request, Config: configBody, OriginalIPv4Forwarding: originalForwarding,
		}))
	}
	if !host.ServiceActive(ctx, request.Name) {
		return Result{}, errors.Join(errors.New("wg-quick service became inactive"),
			s.rollbackCreateInterface(ctx, operationID, &interfaceSnapshot{
				Request: request, Config: configBody, OriginalIPv4Forwarding: originalForwarding,
			}))
	}
	if err := s.repository.FinalizeControlOperation(
		ctx, operationID, "create_interface", "interface", operationID, 0, revision,
	); err != nil {
		return Result{}, err
	}
	return Result{
		OperationID: operationID, State: agentoperation.StateCommitted,
		InterfaceID: operationID, InterfaceRevision: revision,
	}, nil
}

func (s *Service) applyInterfaceHost(
	ctx context.Context,
	operationID string,
	request InterfaceRequest,
	plan network.Plan,
	configBody []byte,
) error {
	marker := "WireGate-Operation: " + operationID
	if request.FirewallMode == string(network.FirewallManagedNFT) {
		directory := filepath.Join(s.networkRoot, request.Name)
		up := append([]byte("# "+marker+"\n"), plan.UpNFT...)
		down := append([]byte("# "+marker+"\n"), plan.DownNFT...)
		if err := host.WriteOwnedFile(filepath.Join(directory, "up.nft"), up, 0o600, 0o700); err != nil {
			return fmt.Errorf("write nftables up asset: %w", err)
		}
		if err := host.WriteOwnedFile(filepath.Join(directory, "down.nft"), down, 0o600, 0o700); err != nil {
			return fmt.Errorf("write nftables down asset: %w", err)
		}
		if err := host.ValidateNFT(ctx, filepath.Join(directory, "up.nft")); err != nil {
			return err
		}
	}
	if len(plan.Sysctl) > 0 {
		body := append([]byte("# "+marker+"\n"), plan.Sysctl...)
		path := filepath.Join(s.sysctlRoot, "90-wiregate-"+request.Name+".conf")
		if err := host.WriteOwnedFile(path, body, 0o600, 0o755); err != nil {
			return fmt.Errorf("write sysctl asset: %w", err)
		}
		if err := host.SetSysctlIPv4Forwarding("1"); err != nil {
			return fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
	}
	if err := s.files.CreateConfig(request.Name, configBody, 0o600); err != nil {
		return fmt.Errorf("create WireGuard config: %w", err)
	}
	if request.AutoStart {
		if err := host.EnableService(ctx, request.Name); err != nil {
			return err
		}
	}
	if err := host.StartService(ctx, request.Name); err != nil {
		return err
	}
	return nil
}

func (s *Service) rollbackCreateInterface(
	ctx context.Context,
	operationID string,
	snapshot *interfaceSnapshot,
) error {
	metadata, _ := s.repository.GetOperationMetadata(ctx, operationID)
	switch metadata.State {
	case agentoperation.StateSnapshotted, agentoperation.StateExecuting, agentoperation.StateVerifying:
		if err := s.repository.TransitionOperation(
			ctx, operationID, metadata.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "CREATE_INTERFACE_FAILED", Message: "interface creation failed"},
		); err != nil {
			return err
		}
	case agentoperation.StateRollingBack:
	default:
		return nil
	}
	marker := "WireGate-Operation: " + operationID
	var rollbackErrors []error
	if host.ServiceActive(ctx, snapshot.Request.Name) {
		rollbackErrors = append(rollbackErrors, host.StopService(ctx, snapshot.Request.Name))
	}
	if snapshot.Request.AutoStart && host.ServiceEnabled(ctx, snapshot.Request.Name) {
		rollbackErrors = append(rollbackErrors, host.DisableService(ctx, snapshot.Request.Name))
	}
	if snapshot.Request.FirewallMode == string(network.FirewallManagedNFT) {
		directory := filepath.Join(s.networkRoot, snapshot.Request.Name)
		downPath := filepath.Join(directory, "down.nft")
		if _, err := os.Stat(downPath); err == nil {
			_ = host.ApplyNFT(ctx, downPath)
		}
		rollbackErrors = append(rollbackErrors,
			host.RemoveOwnedFile(filepath.Join(directory, "up.nft"), marker),
			host.RemoveOwnedFile(downPath, marker),
		)
	}
	if snapshot.OriginalIPv4Forwarding != "" {
		rollbackErrors = append(rollbackErrors,
			host.SetSysctlIPv4Forwarding(snapshot.OriginalIPv4Forwarding),
			host.RemoveOwnedFile(
				filepath.Join(s.sysctlRoot, "90-wiregate-"+snapshot.Request.Name+".conf"), marker,
			),
		)
	}
	rollbackErrors = append(rollbackErrors,
		host.RemoveOwnedFile(filepath.Join(s.configRoot, snapshot.Request.Name+".conf"), marker),
	)
	if joined := errors.Join(rollbackErrors...); joined != nil {
		_ = s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateRollingBack, agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: "interface rollback failed"},
		)
		return joined
	}
	return s.repository.RollbackManagedInterface(ctx, operationID)
}

func (s *Service) Recover(ctx context.Context) error {
	if err := s.repairLegacyRuntimeFingerprints(ctx); err != nil {
		return err
	}
	records, err := s.repository.RecoverableOperations(ctx)
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, record := range records {
		metadata, err := s.repository.GetOperationMetadata(ctx, record.ID)
		if err != nil {
			recoveryErrors = append(recoveryErrors, err)
			continue
		}
		switch record.State {
		case agentoperation.StatePending:
			err = s.repository.TransitionOperation(
				ctx, record.ID, record.State, agentoperation.StateExpired,
				&agentoperation.Failure{Code: "RECOVERY_EXPIRED", Message: "pending preview expired during restart"},
			)
		case agentoperation.StateValidated:
			failure := &agentoperation.Failure{Code: "RECOVERY_REJECTED", Message: "validated operation had no durable snapshot"}
			if record.Type == "create_interface" {
				err = s.repository.RejectManagedInterfaceReservation(ctx, record.ID, failure)
			} else {
				err = s.repository.TransitionOperation(ctx, record.ID, record.State, agentoperation.StateRejected, failure)
			}
		case agentoperation.StateVerifying:
			err = s.recoverVerifying(ctx, metadata)
		case agentoperation.StateSnapshotted, agentoperation.StateExecuting,
			agentoperation.StateRollingBack:
			secretContext, envelope, loadErr := s.repository.LoadOperationSnapshot(ctx, record.ID)
			if loadErr != nil {
				err = loadErr
				break
			}
			master, loadErr := s.masterKey(envelope.KeyVersion)
			if loadErr != nil {
				err = loadErr
				break
			}
			payload, openErr := secret.Open(master, secretContext, envelope)
			wipe(master)
			if openErr != nil {
				err = openErr
				break
			}
			err = s.recoverSnapshotted(ctx, metadata, payload)
			wipe(payload)
		case agentoperation.StateRollbackFailed:
			err = nil
		}
		if err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover interface operation %s: %w", record.ID, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *Service) repairLegacyRuntimeFingerprints(ctx context.Context) error {
	interfaces, err := s.repository.ListInterfaces(ctx)
	if err != nil {
		return err
	}
	for _, record := range interfaces {
		if !record.RuntimePresent || (record.ManagementMode != "managed" && record.ManagementMode != "adopted") {
			continue
		}
		device, err := host.InspectDevice(record.Name)
		if err != nil || !device.Present {
			if err != nil {
				return err
			}
			continue
		}
		if _, err := s.repository.RepairLegacyRuntimeFingerprint(
			ctx, record.ID, device.LegacyFingerprint, device.Fingerprint,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recoverVerifying(ctx context.Context, metadata repository.OperationMetadata) error {
	interfaceRecord, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
	if err != nil {
		return err
	}
	config, err := s.files.ReadConfig(interfaceRecord.Name)
	if err != nil {
		return err
	}
	defer wipe(config.Body)
	if metadata.ProposedFileHash == "" || config.Hash != metadata.ProposedFileHash ||
		interfaceRecord.FileHash != metadata.ProposedFileHash {
		failure := &agentoperation.Failure{Code: "RECOVERY_MANUAL_INTERVENTION", Message: "verified metadata does not match host config"}
		_ = s.repository.TransitionOperation(ctx, metadata.ID, agentoperation.StateVerifying,
			agentoperation.StateRollingBack,
			failure)
		_ = s.repository.TransitionOperation(ctx, metadata.ID, agentoperation.StateRollingBack,
			agentoperation.StateRollbackFailed, failure)
		return errors.New("verifying operation requires manual intervention")
	}
	before := int64(0)
	if metadata.ExpectedRevision != nil {
		before = *metadata.ExpectedRevision
	}
	targetType, targetID := "interface", metadata.InterfaceID
	if metadata.Type == "create_peer" {
		targetType, targetID = "peer", metadata.ID
	} else if metadata.Type == "update_peer" {
		var intent peerUpdateIntent
		if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil {
			return err
		}
		targetType, targetID = "peer", intent.PeerID
	} else if strings.HasSuffix(metadata.Type, "_peer") {
		var intent lifecycleIntent
		if err := json.Unmarshal([]byte(metadata.IntentJSON), &intent); err != nil {
			return err
		}
		targetType, targetID = "peer", intent.PeerID
	}
	return s.repository.FinalizeControlOperation(ctx, metadata.ID, metadata.Type,
		targetType, targetID, before, interfaceRecord.Revision)
}

func (s *Service) recoverSnapshotted(
	ctx context.Context,
	metadata repository.OperationMetadata,
	payload []byte,
) error {
	switch metadata.Type {
	case "create_interface":
		var snapshot interfaceSnapshot
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return err
		}
		unlock, err := s.lockInterface(snapshot.Request.Name)
		if err != nil {
			return err
		}
		defer unlock()
		return s.rollbackCreateInterface(ctx, metadata.ID, &snapshot)
	case "create_peer":
		var snapshot peerSnapshot
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return err
		}
		interfaceRecord, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
		if err != nil {
			return err
		}
		unlock, err := s.lockInterface(interfaceRecord.Name)
		if err != nil {
			return err
		}
		defer unlock()
		return s.rollbackPeerCreate(ctx, metadata.ID, interfaceRecord, &snapshot, true)
	case "update_peer":
		var snapshot peerUpdateSnapshot
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return err
		}
		peer, err := s.repository.GetPeer(ctx, snapshot.Intent.PeerID)
		if err != nil {
			return err
		}
		interfaceRecord, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
		if err != nil {
			return err
		}
		material, err := s.repository.ClientMaterial(ctx, peer.ID)
		if err != nil {
			return err
		}
		var psk []byte
		if material.PresharedKey != nil {
			psk, err = s.openPeerSecret(material.PresharedKey)
			if err != nil {
				return err
			}
		}
		defer wipe(psk)
		unlock, err := s.lockInterface(interfaceRecord.Name)
		if err != nil {
			return err
		}
		defer unlock()
		return s.rollbackPeerUpdate(ctx, metadata.ID, interfaceRecord, peer, psk, &snapshot, true)
	case "disable_peer", "enable_peer", "revoke_peer":
		var snapshot lifecycleSnapshot
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return err
		}
		peer, err := s.repository.GetPeer(ctx, snapshot.Intent.PeerID)
		if err != nil {
			return err
		}
		interfaceRecord, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
		if err != nil {
			return err
		}
		var psk []byte
		material, err := s.repository.ClientMaterial(ctx, peer.ID)
		if err == nil && material.PresharedKey != nil {
			psk, err = s.openPeerSecret(material.PresharedKey)
		}
		if err != nil {
			return err
		}
		defer wipe(psk)
		unlock, err := s.lockInterface(interfaceRecord.Name)
		if err != nil {
			return err
		}
		defer unlock()
		return s.rollbackLifecycle(ctx, metadata.ID, interfaceRecord, peer, psk, &snapshot, true)
	default:
		return fmt.Errorf("unsupported recoverable control operation %s", metadata.Type)
	}
}

func (s *Service) preflightCreate(ctx context.Context, request InterfaceRequest) ([]Issue, error) {
	if err := validation.InterfaceName(request.Name); err != nil || !s.allowed(request.Name) {
		return nil, fmt.Errorf("%w: interface name is invalid or outside the allowlist", ErrInvalid)
	}
	if err := host.RequireNativeTools(request.FirewallMode == string(network.FirewallManagedNFT)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrecondition, err)
	}
	if exists, err := host.InterfaceExists(request.Name); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("%w: interface %s already exists", ErrConflict, request.Name)
	}
	configPath := filepath.Join(s.configRoot, request.Name+".conf")
	if _, err := os.Lstat(configPath); err == nil {
		return nil, fmt.Errorf("%w: config path already exists", ErrConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := host.UDPPortAvailable(request.ListenPort); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	candidates, err := interfacePrefixes(request.Addresses)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	occupied, err := host.OccupiedPrefixes()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrecondition, err)
	}
	if err := network.RejectNetworkOverlap(candidates, occupied); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if _, err := buildNetworkPlan("01900000-0000-7000-8000-000000000000", request); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var issues []Issue
	if request.FirewallMode == string(network.FirewallManagedNFT) {
		conflict, err := host.ManagedNFTConflict(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPrecondition, err)
		}
		if conflict != "" && request.DeploymentProfile != string(network.ProfileServerOnly) {
			return nil, fmt.Errorf("%w: %s", ErrPrecondition, conflict)
		}
		if conflict != "" {
			issues = append(issues, Issue{
				Code: "EXTERNAL_FORWARD_DROP_PRESENT", Severity: "warning", Field: "firewall_mode",
				Summary: conflict, Remediation: "Server-only mode does not forward traffic; verify the UDP input path after creation.",
			})
		}
	}
	return issues, nil
}

func (s *Service) interfaceResources(
	operationID string,
	request InterfaceRequest,
	plan network.Plan,
	configHash string,
) []repository.ManagedResourceInput {
	result := []repository.ManagedResourceInput{{
		Kind: "wireguard_config", Path: filepath.Join(s.configRoot, request.Name+".conf"),
		Fingerprint: configHash,
	}}
	if request.FirewallMode == string(network.FirewallManagedNFT) {
		directory := filepath.Join(s.networkRoot, request.Name)
		result = append(result,
			repository.ManagedResourceInput{Kind: "nft_up", Path: filepath.Join(directory, "up.nft"), Fingerprint: filesystem.SHA256(plan.UpNFT)},
			repository.ManagedResourceInput{Kind: "nft_down", Path: filepath.Join(directory, "down.nft"), Fingerprint: filesystem.SHA256(plan.DownNFT)},
		)
	}
	if len(plan.Sysctl) > 0 {
		result = append(result, repository.ManagedResourceInput{
			Kind: "sysctl", Path: filepath.Join(s.sysctlRoot, "90-wiregate-"+request.Name+".conf"),
			Fingerprint: filesystem.SHA256(plan.Sysctl),
		})
	}
	if request.AutoStart {
		result = append(result, repository.ManagedResourceInput{Kind: "systemd_enable", Fingerprint: operationID})
	}
	return result
}

func (s *Service) lockInterface(name string) (func(), error) {
	s.localLocksMu.Lock()
	lock := s.localLocks[name]
	if lock == nil {
		lock = &sync.Mutex{}
		s.localLocks[name] = lock
	}
	s.localLocksMu.Unlock()
	lock.Lock()
	releaseOS, err := host.LockInterface(name)
	if err != nil {
		lock.Unlock()
		return nil, err
	}
	return func() {
		_ = releaseOS()
		lock.Unlock()
	}, nil
}

func (s *Service) rejectReservation(ctx context.Context, operationID string) {
	_ = s.repository.RejectManagedInterfaceReservation(ctx, operationID, &agentoperation.Failure{
		Code: "CREATE_INTERFACE_PREPARE_FAILED", Message: "interface creation preparation failed",
	})
}

func normalizeInterfaceRequest(request InterfaceRequest) InterfaceRequest {
	request.Name = strings.TrimSpace(request.Name)
	request.DeploymentProfile = strings.TrimSpace(request.DeploymentProfile)
	request.FirewallMode = strings.TrimSpace(request.FirewallMode)
	request.EgressDevice = strings.TrimSpace(request.EgressDevice)
	if request.DeploymentProfile == "" {
		request.DeploymentProfile = string(network.ProfileServerOnly)
	}
	if request.FirewallMode == "" {
		request.FirewallMode = string(network.FirewallExternal)
	}
	for index := range request.Addresses {
		request.Addresses[index] = strings.TrimSpace(request.Addresses[index])
	}
	for index := range request.LANCIDRs {
		request.LANCIDRs[index] = strings.TrimSpace(request.LANCIDRs[index])
	}
	return request
}

func interfacePrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one interface address is required")
	}
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid interface address %q", value)
		}
		if prefix.Addr() == prefix.Masked().Addr() {
			return nil, fmt.Errorf("interface address %s cannot be the network address", prefix)
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func buildNetworkPlan(interfaceID string, request InterfaceRequest) (network.Plan, error) {
	return network.BuildPlan(network.PlanInput{
		InterfaceID: interfaceID, InterfaceName: request.Name,
		Profile:      network.Profile(request.DeploymentProfile),
		FirewallMode: network.FirewallMode(request.FirewallMode),
		ListenPort:   request.ListenPort, TunnelCIDRs: request.Addresses,
		LANCIDRs: request.LANCIDRs, EgressDevice: request.EgressDevice,
	})
}

func validateActor(actor Actor, permission string, adminOnly bool) error {
	if actor.ID == "" || actor.RequestID == "" || actor.IdempotencyKey == "" ||
		actor.Permission != permission || (actor.Role != "admin" && actor.Role != "operator") ||
		(adminOnly && actor.Role != "admin") {
		return ErrPermission
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

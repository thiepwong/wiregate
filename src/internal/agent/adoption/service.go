// File: src/internal/agent/adoption/service.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package adoption

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	"github.com/wiregate-project/wiregate/internal/agent/configdoc"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

var (
	ErrNotEligible      = errors.New("interface is not eligible for adoption")
	ErrRevisionConflict = errors.New("interface revision conflict")
	ErrPermission       = errors.New("adoption permission denied")
)

type Actor struct {
	ID             string
	Role           string
	RequestID      string
	Permission     string
	IdempotencyKey string
	Reason         string
}

type Preview struct {
	OperationID         string
	BaseFileHash        string
	BaseRevision        int64
	PoolCIDRs           []string
	PeerCount           int
	AllocationCount     int
	Warnings            []configdoc.Warning
	HasHooks            bool
	TextualDiffRedacted string
	ExpiresAt           time.Time
}

type CommitResult struct {
	OperationID       string
	State             agentoperation.State
	InterfaceRevision int64
}

type ConfigStore interface {
	ReadConfig(string) (filesystem.ConfigFile, error)
	SupportsAtomicExchange() error
}

type Repository interface {
	GetInterface(context.Context, string) (repository.InterfaceRecord, error)
	PreviewAdoptionImport(context.Context, string) (repository.AdoptionImportPlan, error)
	CreateOperation(context.Context, repository.CreateOperationInput) (agentoperation.Record, error)
	GetOperationMetadata(context.Context, string) (repository.OperationMetadata, error)
	TransitionOperation(context.Context, string, agentoperation.State, agentoperation.State, *agentoperation.Failure) error
	SnapshotOperation(
		context.Context,
		string,
		secret.Context,
		secret.Envelope,
		string,
		string,
		[]repository.StoredSecretInput,
	) error
	ApplyAdoption(context.Context, string) (int64, error)
	FinalizeAdoption(context.Context, string) error
	RollbackAdoption(context.Context, string) error
	ListPeers(context.Context, string) ([]repository.PeerRecord, error)
	RecoverableOperations(context.Context) ([]agentoperation.Record, error)
}

type MasterKeyFunc func(uint32) ([]byte, error)
type FingerprintKeyFunc func() ([]byte, error)

type Service struct {
	repository     Repository
	files          ConfigStore
	masterKey      MasterKeyFunc
	fingerprintKey FingerprintKeyFunc
	gatewayID      string
	keyVersion     uint32
	now            func() time.Time
}

func New(
	repository Repository,
	files ConfigStore,
	masterKey MasterKeyFunc,
	fingerprintKey FingerprintKeyFunc,
	gatewayID string,
	keyVersion uint32,
) (*Service, error) {
	if repository == nil || files == nil || masterKey == nil || fingerprintKey == nil ||
		gatewayID == "" || keyVersion == 0 {
		return nil, errors.New("adoption dependencies, gateway ID and key version are required")
	}
	return &Service{
		repository: repository, files: files, masterKey: masterKey,
		fingerprintKey: fingerprintKey,
		gatewayID:      gatewayID, keyVersion: keyVersion,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *Service) Preview(
	ctx context.Context,
	interfaceID string,
	expectedRevision int64,
	actor Actor,
) (Preview, error) {
	if err := validateActor(actor); err != nil {
		return Preview{}, err
	}
	record, config, document, err := s.inspect(ctx, interfaceID, expectedRevision)
	if err != nil {
		return Preview{}, err
	}
	defer clear(config.Body)
	defer document.Destroy()
	if err := s.files.SupportsAtomicExchange(); err != nil {
		return Preview{}, fmt.Errorf("%w: atomic exchange preflight failed", ErrNotEligible)
	}
	importPlan, err := s.repository.PreviewAdoptionImport(ctx, interfaceID)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %v", ErrNotEligible, err)
	}
	intent, _ := json.Marshal(map[string]any{
		"version": 1, "interface_id": interfaceID, "take_ownership": true,
	})
	diff, _ := json.Marshal(map[string]any{
		"management_mode": map[string]string{"before": "observed", "after": "adopted"},
		"config_rewrite":  false, "peer_profiles_imported": importPlan.PeerCount,
		"address_pools_imported":       importPlan.PoolCIDRs,
		"address_allocations_imported": importPlan.AllocationCount,
	})
	expiresAt := s.now().Add(5 * time.Minute)
	expected := expectedRevision
	operation, err := s.repository.CreateOperation(ctx, repository.CreateOperationInput{
		InterfaceID: interfaceID, Type: "adopt_interface",
		IntentJSON: string(intent), IdempotencyKey: actor.IdempotencyKey,
		ActorID: actor.ID, ActorRole: actor.Role, RequestID: actor.RequestID,
		Reason: actor.Reason, ExpectedRevision: &expected,
		OriginalFileHash: config.Hash, OriginalRuntimeHash: record.RuntimeFingerprint,
		ProposedDiffJSON: string(diff), ExpiresAt: expiresAt,
	})
	if err != nil {
		return Preview{}, err
	}
	analysis := document.Analysis()
	return Preview{
		OperationID: operation.ID, BaseFileHash: config.Hash,
		BaseRevision: expectedRevision, PoolCIDRs: importPlan.PoolCIDRs,
		PeerCount: importPlan.PeerCount, AllocationCount: importPlan.AllocationCount,
		Warnings: analysis.Warnings,
		HasHooks: analysis.HasHooks,
		TextualDiffRedacted: fmt.Sprintf(
			"adopt interface without rewriting config; import %d existing peers, %d pools and %d allocations",
			importPlan.PeerCount, len(importPlan.PoolCIDRs), importPlan.AllocationCount,
		),
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) Commit(ctx context.Context, operationID string, actor Actor) (CommitResult, error) {
	if err := validateActor(actor); err != nil {
		return CommitResult{}, err
	}
	metadata, err := s.repository.GetOperationMetadata(ctx, operationID)
	if err != nil {
		return CommitResult{}, err
	}
	if metadata.Type != "adopt_interface" || metadata.ActorID != actor.ID ||
		metadata.ActorRole != actor.Role || metadata.State != agentoperation.StatePending {
		return CommitResult{}, ErrPermission
	}
	if agentoperation.PreviewExpired(metadata.ExpiresAt, s.now()) {
		_ = s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StatePending, agentoperation.StateExpired,
			&agentoperation.Failure{Code: "PREVIEW_EXPIRED", Message: "operation preview expired"},
		)
		return CommitResult{}, ErrRevisionConflict
	}
	if metadata.ExpectedRevision == nil {
		return CommitResult{}, ErrRevisionConflict
	}
	record, config, document, err := s.inspect(ctx, metadata.InterfaceID, *metadata.ExpectedRevision)
	if err != nil || config.Hash != metadata.OriginalFileHash {
		return CommitResult{}, ErrRevisionConflict
	}
	defer clear(config.Body)
	defer document.Destroy()
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StatePending, agentoperation.StateValidated, nil,
	); err != nil {
		return CommitResult{}, err
	}

	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		s.rejectValidated(ctx, operationID)
		return CommitResult{}, err
	}
	defer wipe(master)
	secretContext := secret.Context{
		GatewayID: s.gatewayID, OwnerType: "operation",
		OwnerID: operationID, Purpose: "snapshot_payload",
	}
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, config.Body, nil)
	if err != nil {
		s.rejectValidated(ctx, operationID)
		return CommitResult{}, err
	}
	synchronized, err := s.synchronizedPSKs(ctx, metadata.InterfaceID, document, master)
	if err != nil {
		s.rejectValidated(ctx, operationID)
		return CommitResult{}, err
	}
	if err := s.repository.SnapshotOperation(
		ctx, operationID, secretContext, envelope, config.Hash, record.RuntimeFingerprint,
		synchronized,
	); err != nil {
		s.rejectValidated(ctx, operationID)
		return CommitResult{}, err
	}
	if err := s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateSnapshotted, agentoperation.StateExecuting, nil,
	); err != nil {
		return CommitResult{}, err
	}
	revision, err := s.repository.ApplyAdoption(ctx, operationID)
	if err != nil {
		s.rollbackMetadataOnly(ctx, operationID)
		return CommitResult{}, err
	}
	updated, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
	if err != nil || updated.ManagementMode != "adopted" || updated.Revision != revision {
		transitionErr := s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateVerifying, agentoperation.StateRollingBack,
			&agentoperation.Failure{Code: "ADOPTION_VERIFY_FAILED", Message: "adoption metadata verification failed"},
		)
		if transitionErr == nil {
			transitionErr = s.repository.RollbackAdoption(ctx, operationID)
			if transitionErr != nil {
				_ = s.repository.TransitionOperation(
					ctx, operationID, agentoperation.StateRollingBack,
					agentoperation.StateRollbackFailed,
					&agentoperation.Failure{
						Code: "ROLLBACK_FAILED", Message: "adoption metadata rollback failed",
					},
				)
			}
		}
		if transitionErr != nil {
			return CommitResult{}, errors.Join(err, transitionErr)
		}
		return CommitResult{}, errors.New("adoption verification failed")
	}
	if err := s.repository.FinalizeAdoption(ctx, operationID); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{
		OperationID: operationID, State: agentoperation.StateCommitted,
		InterfaceRevision: revision,
	}, nil
}

// Recover resolves every durable adoption operation before the agent accepts
// new mutations. It treats pending/validated previews as non-executable,
// retries the atomic metadata transaction only from executing, and uses the
// repository's ownership ledger for rollback.
func (s *Service) Recover(ctx context.Context) error {
	records, err := s.repository.RecoverableOperations(ctx)
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, record := range records {
		if record.Type != "adopt_interface" {
			continue
		}
		if err := s.recoverOne(ctx, record); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf(
				"recover adoption operation %s: %w", record.ID, err,
			))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (s *Service) recoverOne(ctx context.Context, record agentoperation.Record) error {
	switch record.State {
	case agentoperation.StatePending:
		return s.repository.TransitionOperation(
			ctx, record.ID, record.State, agentoperation.StateExpired,
			&agentoperation.Failure{
				Code: "RECOVERY_EXPIRED", Message: "pending preview expired during restart",
			},
		)
	case agentoperation.StateValidated:
		return s.repository.TransitionOperation(
			ctx, record.ID, record.State, agentoperation.StateRejected,
			&agentoperation.Failure{
				Code: "RECOVERY_REJECTED", Message: "validated adoption had no durable snapshot",
			},
		)
	case agentoperation.StateSnapshotted:
		if err := s.repository.TransitionOperation(
			ctx, record.ID, record.State, agentoperation.StateRollingBack,
			&agentoperation.Failure{
				Code: "RECOVERY_ROLLBACK", Message: "snapshotted adoption had not begun execution",
			},
		); err != nil {
			return err
		}
		return s.rollbackOrBlock(ctx, record.ID, "adoption recovery rollback failed")
	case agentoperation.StateExecuting:
		if _, err := s.repository.ApplyAdoption(ctx, record.ID); err != nil {
			metadata, reloadErr := s.repository.GetOperationMetadata(ctx, record.ID)
			if reloadErr == nil && metadata.State == agentoperation.StateVerifying {
				return s.recoverVerifying(ctx, metadata)
			}
			if transitionErr := s.repository.TransitionOperation(
				ctx, record.ID, agentoperation.StateExecuting, agentoperation.StateRollingBack,
				&agentoperation.Failure{
					Code: "RECOVERY_APPLY_FAILED", Message: "adoption metadata apply could not be verified",
				},
			); transitionErr != nil {
				return errors.Join(err, reloadErr, transitionErr)
			}
			if rollbackErr := s.rollbackOrBlock(
				ctx, record.ID, "adoption recovery rollback failed",
			); rollbackErr != nil {
				return errors.Join(err, rollbackErr)
			}
			return nil
		}
		metadata, err := s.repository.GetOperationMetadata(ctx, record.ID)
		if err != nil {
			return err
		}
		return s.recoverVerifying(ctx, metadata)
	case agentoperation.StateVerifying:
		metadata, err := s.repository.GetOperationMetadata(ctx, record.ID)
		if err != nil {
			return err
		}
		return s.recoverVerifying(ctx, metadata)
	case agentoperation.StateRollingBack:
		return s.rollbackOrBlock(ctx, record.ID, "adoption recovery rollback failed")
	case agentoperation.StateRollbackFailed:
		// The durable state and partial unique index intentionally block every
		// later mutation on this interface while queries/diagnostics remain up.
		return nil
	default:
		return nil
	}
}

func (s *Service) recoverVerifying(ctx context.Context, metadata repository.OperationMetadata) error {
	record, err := s.repository.GetInterface(ctx, metadata.InterfaceID)
	if err == nil && metadata.ExpectedRevision != nil &&
		record.ManagementMode == "adopted" &&
		record.Revision == *metadata.ExpectedRevision+1 &&
		record.FileHash == metadata.OriginalFileHash {
		return s.repository.FinalizeAdoption(ctx, metadata.ID)
	}
	if transitionErr := s.repository.TransitionOperation(
		ctx, metadata.ID, agentoperation.StateVerifying, agentoperation.StateRollingBack,
		&agentoperation.Failure{
			Code: "RECOVERY_VERIFY_FAILED", Message: "adoption metadata verification failed",
		},
	); transitionErr != nil {
		return errors.Join(err, transitionErr)
	}
	if rollbackErr := s.rollbackOrBlock(
		ctx, metadata.ID, "adoption recovery rollback failed",
	); rollbackErr != nil {
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func (s *Service) rollbackOrBlock(ctx context.Context, operationID, message string) error {
	if err := s.repository.RollbackAdoption(ctx, operationID); err != nil {
		transitionErr := s.repository.TransitionOperation(
			ctx, operationID, agentoperation.StateRollingBack,
			agentoperation.StateRollbackFailed,
			&agentoperation.Failure{Code: "ROLLBACK_FAILED", Message: message},
		)
		return errors.Join(err, transitionErr)
	}
	return nil
}

func (s *Service) synchronizedPSKs(
	ctx context.Context,
	interfaceID string,
	document *configdoc.Document,
	master []byte,
) ([]repository.StoredSecretInput, error) {
	values, err := document.PeerSecrets()
	if err != nil || len(values) == 0 {
		return nil, err
	}
	fingerprintKey, err := s.fingerprintKey()
	if err != nil {
		return nil, err
	}
	defer wipe(fingerprintKey)
	peers, err := s.repository.ListPeers(ctx, interfaceID)
	if err != nil {
		return nil, err
	}
	peerIDs := make(map[string]string, len(peers))
	for _, peer := range peers {
		peerIDs[peer.PublicKey] = peer.ID
	}
	result := make([]repository.StoredSecretInput, 0, len(values))
	for _, value := range values {
		peerID := peerIDs[value.PublicKey]
		if peerID == "" {
			wipe(value.PresharedKey)
			return nil, errors.New("adoption PSK owner is missing from indexed peers")
		}
		fingerprint, err := secret.Fingerprint(fingerprintKey, value.PresharedKey)
		if err != nil {
			wipe(value.PresharedKey)
			return nil, err
		}
		secretContext := secret.Context{
			GatewayID: s.gatewayID, OwnerType: "peer",
			OwnerID: peerID, Purpose: "preshared_key",
		}
		canonical := make([]byte, base64.StdEncoding.EncodedLen(len(value.PresharedKey)))
		base64.StdEncoding.Encode(canonical, value.PresharedKey)
		envelope, err := secret.Seal(
			master, s.keyVersion, secretContext, canonical, fingerprint,
		)
		wipe(canonical)
		wipe(value.PresharedKey)
		if err != nil {
			return nil, err
		}
		result = append(result, repository.StoredSecretInput{
			Context: secretContext, Envelope: envelope,
		})
	}
	return result, nil
}

func (s *Service) inspect(
	ctx context.Context,
	interfaceID string,
	expectedRevision int64,
) (repository.InterfaceRecord, filesystem.ConfigFile, *configdoc.Document, error) {
	record, err := s.repository.GetInterface(ctx, interfaceID)
	if err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, err
	}
	if record.ManagementMode != "observed" || record.Backend != "wg_quick" ||
		!record.ConfigPresent || record.SaveConfigDetected {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, ErrNotEligible
	}
	if record.Revision != expectedRevision {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, ErrRevisionConflict
	}
	config, err := s.files.ReadConfig(record.Name)
	if err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, err
	}
	if config.UID != 0 || config.Mode.Perm()&0o077 != 0 {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, ErrNotEligible
	}
	if config.Hash != record.FileHash {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, ErrRevisionConflict
	}
	document, err := configdoc.Parse(config.Body)
	if err != nil {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, err
	}
	if err := document.AdoptionSafe(); err != nil || document.Analysis().SaveConfig {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, ErrNotEligible
	}
	if !bytes.Equal(document.Bytes(), config.Body) {
		return repository.InterfaceRecord{}, filesystem.ConfigFile{}, nil, errors.New("lossless parser invariant failed")
	}
	return record, config, document, nil
}

func validateActor(actor Actor) error {
	if actor.ID == "" || actor.Role != "admin" || actor.RequestID == "" ||
		actor.Permission != "interface:adopt" || actor.IdempotencyKey == "" {
		return ErrPermission
	}
	return nil
}

func (s *Service) rejectValidated(ctx context.Context, operationID string) {
	_ = s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateValidated, agentoperation.StateRejected,
		&agentoperation.Failure{Code: "ADOPTION_PREPARE_FAILED", Message: "adoption preparation failed"},
	)
}

func (s *Service) rollbackMetadataOnly(ctx context.Context, operationID string) {
	if s.repository.TransitionOperation(
		ctx, operationID, agentoperation.StateExecuting, agentoperation.StateRollingBack,
		&agentoperation.Failure{Code: "ADOPTION_FAILED", Message: "adoption metadata update failed"},
	) == nil {
		_ = s.rollbackOrBlock(ctx, operationID, "adoption metadata rollback failed")
	}
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

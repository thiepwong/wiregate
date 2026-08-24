// File: src/internal/agent/repository/operation_store.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type CreateOperationInput struct {
	InterfaceID         string
	Type                string
	IntentJSON          string
	IdempotencyKey      string
	ActorID             string
	ActorRole           string
	RequestID           string
	Reason              string
	ExpectedRevision    *int64
	OriginalFileHash    string
	ProposedFileHash    string
	OriginalRuntimeHash string
	ProposedDiffJSON    string
	ExpiresAt           time.Time
	Steps               []agentoperation.StepRecord
}

type OperationMetadata struct {
	ID                  string
	InterfaceID         string
	Type                string
	State               agentoperation.State
	ActorID             string
	ActorRole           string
	RequestID           string
	Reason              string
	IntentJSON          string
	ProposedFileHash    string
	ExpectedRevision    *int64
	OriginalFileHash    string
	OriginalRuntimeHash string
	ExpiresAt           time.Time
}

func (r *Repository) CreateOperation(ctx context.Context, input CreateOperationInput) (agentoperation.Record, error) {
	if input.Type == "" || input.IntentJSON == "" || input.IdempotencyKey == "" ||
		input.ActorID == "" || input.ActorRole == "" || input.RequestID == "" {
		return agentoperation.Record{}, errors.New("operation type, intent, idempotency and actor context are required")
	}
	now := r.now()
	operationID, err := ids.NewV7(now)
	if err != nil {
		return agentoperation.Record{}, err
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return agentoperation.Record{}, fmt.Errorf("begin operation plan: %w", err)
	}
	defer tx.Rollback()

	var replayID string
	var replayIntent string
	replayErr := tx.QueryRowContext(ctx, `
		SELECT id, intent_json FROM operations
		WHERE actor_id = ? AND type = ? AND idempotency_key = ?`,
		input.ActorID, input.Type, input.IdempotencyKey,
	).Scan(&replayID, &replayIntent)
	if replayErr == nil {
		if replayIntent != input.IntentJSON {
			return agentoperation.Record{}, errors.New("idempotency key was already used for different intent")
		}
		_ = tx.Rollback()
		return r.GetOperation(ctx, replayID)
	}
	if !errors.Is(replayErr, sql.ErrNoRows) {
		return agentoperation.Record{}, fmt.Errorf("check operation idempotency: %w", replayErr)
	}

	if input.InterfaceID != "" {
		var active string
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM operations
			WHERE interface_id = ? AND state IN (
				'pending','validated','snapshotted','executing','verifying',
				'rolling_back','rollback_failed'
			) LIMIT 1`, input.InterfaceID).Scan(&active)
		if err == nil {
			return agentoperation.Record{}, fmt.Errorf("operation already in progress for interface")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return agentoperation.Record{}, fmt.Errorf("check active operation: %w", err)
		}
	}

	var expectedRevision any
	if input.ExpectedRevision != nil {
		expectedRevision = *input.ExpectedRevision
	}
	var expiresAt any
	if !input.ExpiresAt.IsZero() {
		expiresAt = input.ExpiresAt.UnixMilli()
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO operations(
			id, interface_id, type, state, plan_version, intent_json,
			idempotency_key, actor_id, actor_role, request_id, reason,
			expected_revision, original_file_hash, proposed_file_hash,
			original_runtime_hash, proposed_diff_json, expires_at_ms,
			created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, 'pending', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		operationID, nullable(input.InterfaceID), input.Type, input.IntentJSON,
		input.IdempotencyKey, input.ActorID, input.ActorRole, input.RequestID,
		nullable(input.Reason), expectedRevision, nullable(input.OriginalFileHash),
		nullable(input.ProposedFileHash), nullable(input.OriginalRuntimeHash),
		nullable(input.ProposedDiffJSON), expiresAt, now.UnixMilli(), now.UnixMilli(),
	)
	if err != nil {
		// Return the original operation for an exact idempotency replay.
		var existingID, existingIntent string
		if lookupErr := tx.QueryRowContext(ctx, `
			SELECT id, intent_json FROM operations
			WHERE actor_id = ? AND type = ? AND idempotency_key = ?`,
			input.ActorID, input.Type, input.IdempotencyKey,
		).Scan(&existingID, &existingIntent); lookupErr == nil {
			if existingIntent != input.IntentJSON {
				return agentoperation.Record{}, errors.New("idempotency key was already used for different intent")
			}
			_ = tx.Rollback()
			return r.GetOperation(ctx, existingID)
		}
		return agentoperation.Record{}, fmt.Errorf("insert operation: %w", err)
	}

	steps := make([]agentoperation.StepRecord, len(input.Steps))
	for index, step := range input.Steps {
		stepID := step.ID
		if stepID == "" {
			stepID, err = ids.NewV7(now.Add(time.Duration(index+1) * time.Nanosecond))
			if err != nil {
				return agentoperation.Record{}, err
			}
		}
		step.ID = stepID
		step.Order = index + 1
		step.State = agentoperation.StepPending
		if step.Kind == "" || step.Name == "" ||
			step.OriginalFingerprint == "" || step.ProposedFingerprint == "" {
			return agentoperation.Record{}, fmt.Errorf("operation step %d is incomplete", index+1)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO operation_steps(
				id, operation_id, step_order, name, state, effect_kind,
				original_fingerprint, proposed_fingerprint
			) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
			step.ID, operationID, step.Order, step.Name, step.Kind,
			step.OriginalFingerprint, step.ProposedFingerprint,
		); err != nil {
			return agentoperation.Record{}, fmt.Errorf("insert operation step: %w", err)
		}
		steps[index] = step
	}
	if err := tx.Commit(); err != nil {
		return agentoperation.Record{}, fmt.Errorf("commit operation plan: %w", err)
	}
	return agentoperation.Record{
		ID: operationID, InterfaceID: input.InterfaceID, Type: input.Type,
		State: agentoperation.StatePending, Steps: steps,
	}, nil
}

func (r *Repository) GetOperation(ctx context.Context, id string) (agentoperation.Record, error) {
	var record agentoperation.Record
	var state string
	var expectedRevision sql.NullInt64
	var finishedAt sql.NullInt64
	var createdAt, updatedAt int64
	if err := r.database.QueryRowContext(ctx, `
		SELECT id, COALESCE(interface_id, ''), type, state, expected_revision,
		       COALESCE(proposed_diff_json, ''), COALESCE(error_code, ''),
		       COALESCE(error_message_redacted, ''), created_at_ms, updated_at_ms,
		       finished_at_ms
		FROM operations WHERE id = ?`, id,
	).Scan(
		&record.ID, &record.InterfaceID, &record.Type, &state,
		&expectedRevision, &record.ProposedDiffJSON, &record.ErrorCode,
		&record.ErrorMessageRedacted, &createdAt, &updatedAt, &finishedAt,
	); err != nil {
		return agentoperation.Record{}, err
	}
	record.State = agentoperation.State(state)
	if expectedRevision.Valid {
		record.ExpectedRevision = &expectedRevision.Int64
	}
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	record.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	if finishedAt.Valid {
		record.FinishedAt = time.UnixMilli(finishedAt.Int64).UTC()
	}
	steps, err := r.operationSteps(ctx, id)
	if err != nil {
		return agentoperation.Record{}, err
	}
	record.Steps = steps
	return record, nil
}

// ListOperations returns newest-first operation records. The cursor is the
// created_at/id pair from the last record on the previous page, which keeps
// pagination deterministic when multiple operations share a millisecond.
func (r *Repository) ListOperations(
	ctx context.Context,
	interfaceID, state string,
	pageSize int,
	beforeCreatedAt time.Time,
	beforeID string,
) ([]agentoperation.Record, error) {
	if pageSize < 1 || pageSize > 201 {
		return nil, errors.New("operation repository page size must be between 1 and 201")
	}
	if state != "" && !validStoredOperationState(state) {
		return nil, errors.New("invalid operation state filter")
	}
	var beforeCreatedAtMS int64
	if !beforeCreatedAt.IsZero() {
		beforeCreatedAtMS = beforeCreatedAt.UnixMilli()
		if beforeID == "" {
			return nil, errors.New("operation cursor requires an ID")
		}
	}
	rows, err := r.database.QueryContext(ctx, `
		SELECT id
		FROM operations
		WHERE (? = '' OR interface_id = ?)
		  AND (? = '' OR state = ?)
		  AND (
		    ? = 0 OR created_at_ms < ? OR
		    (created_at_ms = ? AND id < ?)
		  )
		ORDER BY created_at_ms DESC, id DESC
		LIMIT ?`,
		interfaceID, interfaceID, state, state,
		beforeCreatedAtMS, beforeCreatedAtMS,
		beforeCreatedAtMS, beforeID, pageSize,
	)
	if err != nil {
		return nil, fmt.Errorf("list operations: %w", err)
	}
	defer rows.Close()
	var operationIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan operation ID: %w", err)
		}
		operationIDs = append(operationIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate operations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close operation rows: %w", err)
	}
	records := make([]agentoperation.Record, 0, len(operationIDs))
	for _, id := range operationIDs {
		record, err := r.GetOperation(ctx, id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (r *Repository) GetOperationMetadata(ctx context.Context, id string) (OperationMetadata, error) {
	var result OperationMetadata
	var state string
	var expected sql.NullInt64
	var expires sql.NullInt64
	err := r.database.QueryRowContext(ctx, `
		SELECT id, COALESCE(interface_id, ''), type, state, actor_id, actor_role,
		       request_id, COALESCE(reason, ''), intent_json,
		       COALESCE(proposed_file_hash, ''), expected_revision,
		       COALESCE(original_file_hash, ''), COALESCE(original_runtime_hash, ''),
		       expires_at_ms
		FROM operations WHERE id = ?`, id,
	).Scan(
		&result.ID, &result.InterfaceID, &result.Type, &state,
		&result.ActorID, &result.ActorRole, &result.RequestID, &result.Reason,
		&result.IntentJSON, &result.ProposedFileHash,
		&expected, &result.OriginalFileHash, &result.OriginalRuntimeHash, &expires,
	)
	if err != nil {
		return OperationMetadata{}, err
	}
	result.State = agentoperation.State(state)
	if expected.Valid {
		result.ExpectedRevision = &expected.Int64
	}
	if expires.Valid {
		result.ExpiresAt = time.UnixMilli(expires.Int64).UTC()
	}
	return result, nil
}

func (r *Repository) RecoverableOperations(ctx context.Context) ([]agentoperation.Record, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT id FROM operations
		WHERE state IN ('pending','validated','snapshotted','executing','verifying','rolling_back','rollback_failed')
		ORDER BY created_at_ms`)
	if err != nil {
		return nil, fmt.Errorf("list recoverable operations: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan recoverable operation: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recoverable operations: %w", err)
	}
	result := make([]agentoperation.Record, 0, len(ids))
	for _, id := range ids {
		record, err := r.GetOperation(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func (r *Repository) TransitionOperation(
	ctx context.Context,
	id string,
	from, to agentoperation.State,
	failure *agentoperation.Failure,
) error {
	var code, message any
	if failure != nil {
		code, message = failure.Code, failure.Message
	}
	var finished any
	if agentoperation.IsTerminal(to) {
		finished = r.now().UnixMilli()
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE operations
		SET state = ?, error_code = ?, error_message_redacted = ?,
		    updated_at_ms = ?, finished_at_ms = COALESCE(?, finished_at_ms)
		WHERE id = ? AND state = ?`,
		string(to), code, message, r.now().UnixMilli(), finished, id, string(from),
	)
	if err != nil {
		return fmt.Errorf("transition operation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read operation transition result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("operation state conflict: expected %s", from)
	}
	return nil
}

func (r *Repository) TransitionStep(
	ctx context.Context,
	id string,
	from, to agentoperation.StepState,
	failure *agentoperation.Failure,
) error {
	var message any
	if failure != nil {
		message = failure.Message
	}
	nowMS := r.now().UnixMilli()
	var started, finished any
	if to == agentoperation.StepExecuting || to == agentoperation.StepRollingBack {
		started = nowMS
	}
	if to == agentoperation.StepApplied || to == agentoperation.StepFailed || to == agentoperation.StepRolledBack {
		finished = nowMS
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE operation_steps
		SET state = ?, error_redacted = ?,
		    started_at_ms = COALESCE(started_at_ms, ?),
		    finished_at_ms = COALESCE(?, finished_at_ms)
		WHERE id = ? AND state = ?`,
		string(to), message, started, finished, id, string(from),
	)
	if err != nil {
		return fmt.Errorf("transition operation step: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("operation step state conflict: expected %s", from)
	}
	return nil
}

func (r *Repository) operationSteps(ctx context.Context, operationID string) ([]agentoperation.StepRecord, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT id, step_order, name, effect_kind, state,
		       COALESCE(original_fingerprint, ''), COALESCE(proposed_fingerprint, ''),
		       COALESCE(error_redacted, '')
		FROM operation_steps
		WHERE operation_id = ?
		ORDER BY step_order`, operationID)
	if err != nil {
		return nil, fmt.Errorf("list operation steps: %w", err)
	}
	defer rows.Close()
	var steps []agentoperation.StepRecord
	for rows.Next() {
		var step agentoperation.StepRecord
		var state string
		if err := rows.Scan(
			&step.ID, &step.Order, &step.Name, &step.Kind, &state,
			&step.OriginalFingerprint, &step.ProposedFingerprint, &step.ErrorRedacted,
		); err != nil {
			return nil, fmt.Errorf("scan operation step: %w", err)
		}
		step.State = agentoperation.StepState(state)
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

func validStoredOperationState(state string) bool {
	switch agentoperation.State(state) {
	case agentoperation.StatePending,
		agentoperation.StateValidated,
		agentoperation.StateSnapshotted,
		agentoperation.StateExecuting,
		agentoperation.StateVerifying,
		agentoperation.StateCommitted,
		agentoperation.StateRollingBack,
		agentoperation.StateRolledBack,
		agentoperation.StateRollbackFailed,
		agentoperation.StateRejected,
		agentoperation.StateExpired:
		return true
	default:
		return false
	}
}

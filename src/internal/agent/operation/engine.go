package operation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

type State string

const (
	StatePending        State = "pending"
	StateValidated      State = "validated"
	StateSnapshotted    State = "snapshotted"
	StateExecuting      State = "executing"
	StateVerifying      State = "verifying"
	StateCommitted      State = "committed"
	StateRollingBack    State = "rolling_back"
	StateRolledBack     State = "rolled_back"
	StateRollbackFailed State = "rollback_failed"
	StateRejected       State = "rejected"
	StateExpired        State = "expired"
)

type StepState string

const (
	StepPending     StepState = "pending"
	StepExecuting   StepState = "executing"
	StepApplied     StepState = "applied"
	StepFailed      StepState = "failed"
	StepRollingBack StepState = "rolling_back"
	StepRolledBack  StepState = "rolled_back"
)

type Failure struct {
	Code    string
	Message string
}

type Record struct {
	ID                   string
	InterfaceID          string
	Type                 string
	State                State
	ExpectedRevision     *int64
	ProposedDiffJSON     string
	ErrorCode            string
	ErrorMessageRedacted string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	FinishedAt           time.Time
	Steps                []StepRecord
}

type StepRecord struct {
	ID                  string
	Order               int
	Name                string
	Kind                string
	State               StepState
	OriginalFingerprint string
	ProposedFingerprint string
	ErrorRedacted       string
}

type Journal interface {
	TransitionOperation(context.Context, string, State, State, *Failure) error
	TransitionStep(context.Context, string, StepState, StepState, *Failure) error
}

// Effect implementations are typed adapters. They must never accept a shell
// command assembled from user input.
type Effect interface {
	Name() string
	Inspect(context.Context) (string, error)
	Apply(context.Context) error
	Rollback(context.Context) error
	Idempotent() bool
}

type VerifyFunc func(context.Context) error

type Engine struct {
	journal Journal
}

func NewEngine(journal Journal) *Engine {
	return &Engine{journal: journal}
}

func (e *Engine) Execute(ctx context.Context, record *Record, effects []Effect, verify VerifyFunc) error {
	if err := validatePlan(record, effects); err != nil {
		return err
	}
	if record.State != StateSnapshotted {
		return fmt.Errorf("operation %s must be snapshotted before execution", record.ID)
	}
	if err := e.operationTransition(ctx, record, StateSnapshotted, StateExecuting, nil); err != nil {
		return err
	}
	for index := range record.Steps {
		if err := e.applyStep(ctx, record, index, effects[index], false); err != nil {
			return e.failAndRollback(ctx, record, effects, err)
		}
	}
	if err := e.operationTransition(ctx, record, StateExecuting, StateVerifying, nil); err != nil {
		return e.failAndRollback(ctx, record, effects, err)
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return e.failAndRollback(ctx, record, effects, fmt.Errorf("verify operation: %w", err))
		}
	}
	if err := e.operationTransition(ctx, record, StateVerifying, StateCommitted, nil); err != nil {
		return err
	}
	return nil
}

// Recover resumes a durable non-terminal operation. It never retries an
// ambiguous or non-idempotent effect. Such states immediately enter rollback.
func (e *Engine) Recover(ctx context.Context, record *Record, effects []Effect, verify VerifyFunc) error {
	if err := validatePlan(record, effects); err != nil {
		return err
	}
	switch record.State {
	case StatePending:
		return e.operationTransition(ctx, record, StatePending, StateExpired, &Failure{
			Code: "RECOVERY_EXPIRED", Message: "pending preview expired during restart",
		})
	case StateValidated:
		return e.operationTransition(ctx, record, StateValidated, StateRejected, &Failure{
			Code: "RECOVERY_REJECTED", Message: "validated operation had no durable snapshot",
		})
	case StateSnapshotted:
		for _, step := range record.Steps {
			if step.State != StepPending {
				return e.recoverExecuting(ctx, record, effects, verify)
			}
		}
		if err := e.operationTransition(ctx, record, StateSnapshotted, StateRollingBack, nil); err != nil {
			return err
		}
		return e.finishRolledBack(ctx, record)
	case StateExecuting:
		return e.recoverExecuting(ctx, record, effects, verify)
	case StateVerifying:
		if verify == nil || verify(ctx) == nil {
			return e.operationTransition(ctx, record, StateVerifying, StateCommitted, nil)
		}
		return e.failAndRollback(ctx, record, effects, errors.New("recovery verification failed"))
	case StateRollingBack:
		return e.rollback(ctx, record, effects)
	case StateRollbackFailed:
		return errors.New("operation remains blocked after rollback failure")
	default:
		return nil
	}
}

func (e *Engine) recoverExecuting(ctx context.Context, record *Record, effects []Effect, verify VerifyFunc) error {
	if record.State == StateSnapshotted {
		if err := e.operationTransition(ctx, record, StateSnapshotted, StateExecuting, nil); err != nil {
			return err
		}
	}
	for index := range record.Steps {
		step := &record.Steps[index]
		switch step.State {
		case StepApplied:
			continue
		case StepPending:
			if err := e.applyStep(ctx, record, index, effects[index], true); err != nil {
				return e.failAndRollback(ctx, record, effects, err)
			}
		case StepExecuting, StepFailed:
			fingerprint, err := effects[index].Inspect(ctx)
			switch {
			case err != nil:
				return e.failAndRollback(ctx, record, effects, fmt.Errorf("inspect step %s: %w", step.Name, err))
			case fingerprint == step.ProposedFingerprint:
				if err := e.stepTransition(ctx, step, step.State, StepApplied, nil); err != nil {
					return err
				}
			case fingerprint == step.OriginalFingerprint && effects[index].Idempotent():
				if step.State == StepFailed {
					if err := e.stepTransition(ctx, step, StepFailed, StepExecuting, nil); err != nil {
						return err
					}
				}
				if err := effects[index].Apply(ctx); err != nil {
					return e.failAndRollback(ctx, record, effects, fmt.Errorf("retry step %s: %w", step.Name, err))
				}
				if err := e.verifyStep(ctx, step, effects[index]); err != nil {
					return e.failAndRollback(ctx, record, effects, err)
				}
			default:
				return e.failAndRollback(ctx, record, effects, fmt.Errorf("step %s is in an ambiguous external state", step.Name))
			}
		default:
			return e.failAndRollback(ctx, record, effects, fmt.Errorf("step %s has invalid recovery state %s", step.Name, step.State))
		}
	}
	if err := e.operationTransition(ctx, record, StateExecuting, StateVerifying, nil); err != nil {
		return err
	}
	if verify != nil {
		if err := verify(ctx); err != nil {
			return e.failAndRollback(ctx, record, effects, err)
		}
	}
	return e.operationTransition(ctx, record, StateVerifying, StateCommitted, nil)
}

func (e *Engine) applyStep(ctx context.Context, record *Record, index int, effect Effect, recovery bool) error {
	step := &record.Steps[index]
	if step.State != StepPending {
		return fmt.Errorf("step %s is not pending", step.Name)
	}
	if err := e.stepTransition(ctx, step, StepPending, StepExecuting, nil); err != nil {
		return err
	}
	fingerprint, err := effect.Inspect(ctx)
	if err != nil {
		_ = e.stepTransition(ctx, step, StepExecuting, StepFailed, safeFailure("STEP_INSPECT_FAILED", err))
		return fmt.Errorf("inspect step %s: %w", step.Name, err)
	}
	switch fingerprint {
	case step.ProposedFingerprint:
		return e.stepTransition(ctx, step, StepExecuting, StepApplied, nil)
	case step.OriginalFingerprint:
		if recovery && !effect.Idempotent() {
			return fmt.Errorf("step %s cannot be safely retried", step.Name)
		}
	default:
		return fmt.Errorf("step %s original fingerprint changed", step.Name)
	}
	if err := effect.Apply(ctx); err != nil {
		_ = e.stepTransition(ctx, step, StepExecuting, StepFailed, safeFailure("STEP_APPLY_FAILED", err))
		return fmt.Errorf("apply step %s: %w", step.Name, err)
	}
	return e.verifyStep(ctx, step, effect)
}

func (e *Engine) verifyStep(ctx context.Context, step *StepRecord, effect Effect) error {
	fingerprint, err := effect.Inspect(ctx)
	if err != nil {
		_ = e.stepTransition(ctx, step, StepExecuting, StepFailed, safeFailure("STEP_VERIFY_FAILED", err))
		return fmt.Errorf("verify step %s: %w", step.Name, err)
	}
	if fingerprint != step.ProposedFingerprint {
		err := errors.New("proposed fingerprint not observed")
		_ = e.stepTransition(ctx, step, StepExecuting, StepFailed, safeFailure("STEP_VERIFY_FAILED", err))
		return fmt.Errorf("verify step %s: %w", step.Name, err)
	}
	return e.stepTransition(ctx, step, StepExecuting, StepApplied, nil)
}

func (e *Engine) failAndRollback(ctx context.Context, record *Record, effects []Effect, cause error) error {
	failure := safeFailure("OPERATION_FAILED", cause)
	switch record.State {
	case StateSnapshotted, StateExecuting, StateVerifying:
		if err := e.operationTransition(ctx, record, record.State, StateRollingBack, failure); err != nil {
			return errors.Join(cause, err)
		}
	case StateRollingBack:
	default:
		return cause
	}
	if err := e.rollback(ctx, record, effects); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (e *Engine) rollback(ctx context.Context, record *Record, effects []Effect) error {
	for index := len(record.Steps) - 1; index >= 0; index-- {
		step := &record.Steps[index]
		if step.State != StepApplied && step.State != StepExecuting && step.State != StepFailed && step.State != StepRollingBack {
			continue
		}
		if step.State != StepRollingBack {
			if err := e.stepTransition(ctx, step, step.State, StepRollingBack, nil); err != nil {
				return e.rollbackFailed(ctx, record, err)
			}
		}
		fingerprint, err := effects[index].Inspect(ctx)
		if err != nil {
			return e.rollbackFailed(ctx, record, fmt.Errorf("inspect rollback step %s: %w", step.Name, err))
		}
		if fingerprint != step.OriginalFingerprint {
			if err := effects[index].Rollback(ctx); err != nil {
				return e.rollbackFailed(ctx, record, fmt.Errorf("rollback step %s: %w", step.Name, err))
			}
			fingerprint, err = effects[index].Inspect(ctx)
			if err != nil || fingerprint != step.OriginalFingerprint {
				return e.rollbackFailed(ctx, record, fmt.Errorf("rollback verification failed for step %s", step.Name))
			}
		}
		if err := e.stepTransition(ctx, step, StepRollingBack, StepRolledBack, nil); err != nil {
			return e.rollbackFailed(ctx, record, err)
		}
	}
	return e.finishRolledBack(ctx, record)
}

func (e *Engine) finishRolledBack(ctx context.Context, record *Record) error {
	return e.operationTransition(ctx, record, StateRollingBack, StateRolledBack, nil)
}

func (e *Engine) rollbackFailed(ctx context.Context, record *Record, cause error) error {
	failure := safeFailure("ROLLBACK_FAILED", cause)
	if err := e.operationTransition(ctx, record, StateRollingBack, StateRollbackFailed, failure); err != nil {
		return errors.Join(cause, err)
	}
	return fmt.Errorf("rollback failed: %w", cause)
}

func (e *Engine) operationTransition(ctx context.Context, record *Record, from, to State, failure *Failure) error {
	if record.State != from {
		return fmt.Errorf("operation state changed: expected %s, got %s", from, record.State)
	}
	if !validOperationTransition(from, to) {
		return fmt.Errorf("invalid operation transition %s -> %s", from, to)
	}
	if err := e.journal.TransitionOperation(ctx, record.ID, from, to, failure); err != nil {
		return err
	}
	record.State = to
	return nil
}

func (e *Engine) stepTransition(ctx context.Context, step *StepRecord, from, to StepState, failure *Failure) error {
	if step.State != from {
		return fmt.Errorf("step state changed: expected %s, got %s", from, step.State)
	}
	if !validStepTransition(from, to) {
		return fmt.Errorf("invalid step transition %s -> %s", from, to)
	}
	if err := e.journal.TransitionStep(ctx, step.ID, from, to, failure); err != nil {
		return err
	}
	step.State = to
	return nil
}

func validatePlan(record *Record, effects []Effect) error {
	if record == nil || record.ID == "" {
		return errors.New("operation record is required")
	}
	if len(record.Steps) != len(effects) {
		return errors.New("operation step/effect count mismatch")
	}
	orders := make([]int, 0, len(record.Steps))
	for index := range record.Steps {
		if record.Steps[index].ID == "" ||
			record.Steps[index].Name != effects[index].Name() ||
			record.Steps[index].OriginalFingerprint == "" ||
			record.Steps[index].ProposedFingerprint == "" {
			return fmt.Errorf("invalid operation step at index %d", index)
		}
		orders = append(orders, record.Steps[index].Order)
	}
	if !slices.IsSorted(orders) {
		return errors.New("operation steps are not ordered")
	}
	return nil
}

func validOperationTransition(from, to State) bool {
	allowed := map[State][]State{
		StatePending:     {StateValidated, StateRejected, StateExpired},
		StateValidated:   {StateSnapshotted, StateRejected},
		StateSnapshotted: {StateExecuting, StateRollingBack},
		StateExecuting:   {StateVerifying, StateRollingBack},
		StateVerifying:   {StateCommitted, StateRollingBack},
		StateRollingBack: {StateRolledBack, StateRollbackFailed},
	}
	return slices.Contains(allowed[from], to)
}

func validStepTransition(from, to StepState) bool {
	allowed := map[StepState][]StepState{
		StepPending:     {StepExecuting},
		StepExecuting:   {StepApplied, StepFailed, StepRollingBack},
		StepFailed:      {StepExecuting, StepRollingBack},
		StepApplied:     {StepRollingBack},
		StepRollingBack: {StepRolledBack},
	}
	return slices.Contains(allowed[from], to)
}

func safeFailure(code string, err error) *Failure {
	// Adapter errors may contain host paths or command output. Durable/public
	// journals store only a stable code and bounded generic text.
	message := "operation step failed"
	if errors.Is(err, context.DeadlineExceeded) {
		message = "operation deadline exceeded"
	} else if errors.Is(err, context.Canceled) {
		message = "operation canceled"
	}
	return &Failure{Code: code, Message: message}
}

func IsTerminal(state State) bool {
	return state == StateCommitted || state == StateRolledBack ||
		state == StateRollbackFailed || state == StateRejected || state == StateExpired
}

func PreviewExpired(expiresAt, now time.Time) bool {
	return expiresAt.IsZero() || !expiresAt.After(now)
}

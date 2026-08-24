// File: src/internal/agent/operation/engine_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package operation

import (
	"context"
	"errors"
	"testing"
)

type memoryJournal struct {
	events []string
}

func (j *memoryJournal) TransitionOperation(_ context.Context, _ string, from, to State, _ *Failure) error {
	j.events = append(j.events, "operation:"+string(from)+"->"+string(to))
	return nil
}

func (j *memoryJournal) TransitionStep(_ context.Context, _ string, from, to StepState, _ *Failure) error {
	j.events = append(j.events, "step:"+string(from)+"->"+string(to))
	return nil
}

type fakeEffect struct {
	name        string
	current     string
	original    string
	proposed    string
	applyErr    error
	rollbackErr error
	idempotent  bool
}

func (e *fakeEffect) Name() string                            { return e.name }
func (e *fakeEffect) Inspect(context.Context) (string, error) { return e.current, nil }
func (e *fakeEffect) Idempotent() bool                        { return e.idempotent }
func (e *fakeEffect) Apply(context.Context) error {
	if e.applyErr != nil {
		return e.applyErr
	}
	e.current = e.proposed
	return nil
}
func (e *fakeEffect) Rollback(context.Context) error {
	if e.rollbackErr != nil {
		return e.rollbackErr
	}
	e.current = e.original
	return nil
}

func record(state State, stepState StepState) *Record {
	return &Record{
		ID: "operation-1", State: state,
		Steps: []StepRecord{{
			ID: "step-1", Order: 1, Name: "file", State: stepState,
			OriginalFingerprint: "old", ProposedFingerprint: "new",
		}},
	}
}

func TestExecutePersistsBeforeEffectAndCommits(t *testing.T) {
	journal := &memoryJournal{}
	effect := &fakeEffect{name: "file", current: "old", original: "old", proposed: "new"}
	item := record(StateSnapshotted, StepPending)
	if err := NewEngine(journal).Execute(context.Background(), item, []Effect{effect}, nil); err != nil {
		t.Fatal(err)
	}
	if item.State != StateCommitted || item.Steps[0].State != StepApplied {
		t.Fatalf("record = %#v", item)
	}
	if len(journal.events) < 5 || journal.events[1] != "step:pending->executing" {
		t.Fatalf("journal events = %#v", journal.events)
	}
}

func TestFailureRollsBackAppliedSteps(t *testing.T) {
	journal := &memoryJournal{}
	first := &fakeEffect{name: "file", current: "old", original: "old", proposed: "new"}
	second := &fakeEffect{name: "runtime", current: "runtime-old", original: "runtime-old", proposed: "runtime-new", applyErr: errors.New("failed")}
	item := &Record{ID: "operation-1", State: StateSnapshotted, Steps: []StepRecord{
		{ID: "step-1", Order: 1, Name: "file", State: StepPending, OriginalFingerprint: "old", ProposedFingerprint: "new"},
		{ID: "step-2", Order: 2, Name: "runtime", State: StepPending, OriginalFingerprint: "runtime-old", ProposedFingerprint: "runtime-new"},
	}}
	if err := NewEngine(journal).Execute(context.Background(), item, []Effect{first, second}, nil); err == nil {
		t.Fatal("failed effect returned success")
	}
	if item.State != StateRolledBack || first.current != "old" {
		t.Fatalf("record=%#v first=%#v", item, first)
	}
}

func TestRecoveryDoesNotRetryAmbiguousNonIdempotentStep(t *testing.T) {
	journal := &memoryJournal{}
	effect := &fakeEffect{
		name: "file", current: "old", original: "old", proposed: "new",
		idempotent: false,
	}
	item := record(StateExecuting, StepExecuting)
	if err := NewEngine(journal).Recover(context.Background(), item, []Effect{effect}, nil); err == nil {
		t.Fatal("non-idempotent interrupted step recovered as success")
	}
	if item.State != StateRolledBack {
		t.Fatalf("state = %s", item.State)
	}
}

func TestRollbackFailureBlocksOperation(t *testing.T) {
	journal := &memoryJournal{}
	effect := &fakeEffect{
		name: "file", current: "new", original: "old", proposed: "new",
		rollbackErr: errors.New("disk unavailable"),
	}
	item := record(StateRollingBack, StepApplied)
	if err := NewEngine(journal).Recover(context.Background(), item, []Effect{effect}, nil); err == nil {
		t.Fatal("rollback failure returned success")
	}
	if item.State != StateRollbackFailed {
		t.Fatalf("state = %s", item.State)
	}
}

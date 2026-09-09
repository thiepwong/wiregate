// File: src/internal/agent/control/actionable_error_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-09-09
// Description: WireGate automated tests.

package control

import (
	"errors"
	"testing"
)

func TestOperatorErrorRetainsCategoryAndSafeMessage(t *testing.T) {
	cause := errors.New("internal host detail")
	err := operatorError(ErrPrecondition, cause, "Refresh and try again.")
	if !errors.Is(err, ErrPrecondition) || !errors.Is(err, cause) {
		t.Fatalf("error chain = %v", err)
	}
	actionable, ok := err.(interface{ PublicMessage() string })
	if !ok || actionable.PublicMessage() != "Refresh and try again." {
		t.Fatalf("public error = %#v", err)
	}
}

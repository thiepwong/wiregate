// File: src/internal/agent/control/actionable_error.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-09-09
// Description: Safe operator-facing control errors with retained internal causes.

package control

import (
	"errors"
	"fmt"
)

type actionableError struct {
	category error
	cause    error
	message  string
}

func (e *actionableError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%v: %v", e.category, e.cause)
	}
	return fmt.Sprintf("%v: %s", e.category, e.message)
}

func (e *actionableError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.category}
	}
	return []error{e.category, e.cause}
}

func (e *actionableError) PublicMessage() string {
	return e.message
}

func operatorError(category, cause error, message string) error {
	if category == nil || message == "" {
		return errors.New("invalid operator error")
	}
	return &actionableError{category: category, cause: cause, message: message}
}

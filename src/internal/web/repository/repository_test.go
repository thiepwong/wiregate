// File: src/internal/web/repository/repository_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package repository

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAppliesWebMigrations(t *testing.T) {
	repository, err := Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer repository.Close()
	if repository.SchemaVersion() != 1 {
		t.Fatalf("SchemaVersion() = %d", repository.SchemaVersion())
	}
}

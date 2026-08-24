// File: src/internal/shared/ids/ids_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package ids

import (
	"regexp"
	"testing"
	"time"
)

func TestNewV7(t *testing.T) {
	at := time.UnixMilli(1_700_000_000_123)
	id, err := NewV7(at)
	if err != nil {
		t.Fatalf("NewV7() error = %v", err)
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(id) {
		t.Fatalf("NewV7() = %q", id)
	}
}

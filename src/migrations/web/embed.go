// File: src/migrations/web/embed.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package webmigrations

import "embed"

// Files contains the immutable web database migration stream.
//
//go:embed *.sql
var Files embed.FS


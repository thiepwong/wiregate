// File: src/migrations/agent/embed.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package agentmigrations

import "embed"

// Files contains the immutable agent database migration stream.
//
//go:embed *.sql
var Files embed.FS


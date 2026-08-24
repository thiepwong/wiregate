package agentmigrations

import "embed"

// Files contains the immutable agent database migration stream.
//
//go:embed *.sql
var Files embed.FS


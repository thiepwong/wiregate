package webmigrations

import "embed"

// Files contains the immutable web database migration stream.
//
//go:embed *.sql
var Files embed.FS


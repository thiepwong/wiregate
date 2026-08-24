// File: src/internal/web/repository/repository.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package repository

import (
	"context"
	"database/sql"

	shareddb "github.com/wiregate-project/wiregate/internal/shared/db"
	webmigrations "github.com/wiregate-project/wiregate/migrations/web"
)

const schemaVersion = 1

// Repository owns web-only state. It never opens the root-owned agent database.
type Repository struct {
	database *sql.DB
}

func Open(ctx context.Context, path string) (*Repository, error) {
	database, err := shareddb.OpenSQLite(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := shareddb.ApplyMigrations(ctx, database, webmigrations.Files); err != nil {
		_ = database.Close()
		return nil, err
	}
	return &Repository{database: database}, nil
}

func (r *Repository) Close() error {
	return r.database.Close()
}

func (r *Repository) SchemaVersion() int {
	return schemaVersion
}

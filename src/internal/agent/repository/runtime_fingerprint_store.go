package repository

import (
	"context"
	"errors"
)

// RepairLegacyRuntimeFingerprint upgrades fingerprints written by the early
// greenfield POC, which omitted firewall mark and peer state. The conditional
// update only succeeds when the authoritative file still matches the last
// applied revision, the stored revision has the exact legacy fingerprint, and
// the current observed runtime has the replacement fingerprint.
func (r *Repository) RepairLegacyRuntimeFingerprint(
	ctx context.Context,
	interfaceID, legacy, replacement string,
) (bool, error) {
	if interfaceID == "" || legacy == "" || replacement == "" || legacy == replacement {
		return false, nil
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var revisionID, revisionFile, revisionRuntime, currentFile, currentRuntime, drift string
	if err := tx.QueryRowContext(ctx, `
		SELECT cr.id, cr.file_hash, COALESCE(cr.runtime_fingerprint, ''),
		       COALESCE(i.file_hash, ''), COALESCE(i.runtime_fingerprint, ''), i.drift_state
		FROM interfaces i
		JOIN config_revisions cr ON cr.id = i.last_applied_revision_id
		WHERE i.id = ? AND i.management_mode IN ('managed','adopted')`, interfaceID,
	).Scan(&revisionID, &revisionFile, &revisionRuntime, &currentFile, &currentRuntime, &drift); err != nil {
		return false, err
	}
	if revisionFile != currentFile || revisionRuntime != legacy || currentRuntime != replacement || drift != "runtime" {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE config_revisions SET runtime_fingerprint = ?
		WHERE id = ? AND runtime_fingerprint = ?`, replacement, revisionID, legacy,
	)
	if err != nil {
		return false, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return false, errors.New("legacy runtime revision changed")
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE interfaces SET drift_state = 'none', updated_at_ms = ?
		WHERE id = ? AND drift_state = 'runtime' AND file_hash = ? AND runtime_fingerprint = ?`,
		r.now().UnixMilli(), interfaceID, currentFile, replacement,
	)
	if err != nil {
		return false, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return false, errors.New("legacy runtime interface changed")
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

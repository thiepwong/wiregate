CREATE TABLE operation_staged_secrets (
    operation_id                TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    secret_envelope_id          TEXT NOT NULL UNIQUE REFERENCES secret_envelopes(id) ON DELETE CASCADE,
    peer_id                     TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    profile_id                  TEXT REFERENCES client_profiles(id) ON DELETE SET NULL,
    previous_secret_envelope_id TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    created_profile             INTEGER NOT NULL DEFAULT 0 CHECK (created_profile IN (0,1)),
    PRIMARY KEY(operation_id, peer_id)
);

CREATE INDEX operation_staged_secrets_operation_idx
ON operation_staged_secrets(operation_id);

DROP INDEX operations_one_active_interface_idx;
CREATE UNIQUE INDEX operations_one_active_interface_idx
ON operations(interface_id)
WHERE interface_id IS NOT NULL
  AND state IN (
      'pending','validated','snapshotted','executing','verifying',
      'rolling_back','rollback_failed'
  );

UPDATE system_state
SET schema_version = 2, updated_at_ms = unixepoch('subsec') * 1000
WHERE singleton_id = 1;

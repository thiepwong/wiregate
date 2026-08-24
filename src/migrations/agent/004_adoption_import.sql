CREATE TABLE adoption_import_ledger (
    operation_id   TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN (
                      'client_profile','address_pool','address_allocation',
                      'allowed_ip_purpose')),
    resource_id   TEXT NOT NULL,
    previous_value TEXT,
    PRIMARY KEY(operation_id, resource_kind, resource_id)
);

CREATE INDEX adoption_import_ledger_operation_idx
ON adoption_import_ledger(operation_id);

UPDATE system_state
SET schema_version = 4, updated_at_ms = unixepoch('subsec') * 1000
WHERE singleton_id = 1;

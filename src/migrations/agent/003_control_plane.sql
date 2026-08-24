ALTER TABLE interfaces ADD COLUMN listen_port INTEGER;
ALTER TABLE interfaces ADD COLUMN public_key TEXT;
ALTER TABLE interfaces ADD COLUMN auto_start INTEGER NOT NULL DEFAULT 0
    CHECK (auto_start IN (0,1));
ALTER TABLE interfaces ADD COLUMN service_state TEXT NOT NULL DEFAULT 'unknown'
    CHECK (service_state IN ('unknown','inactive','active','failed'));

CREATE TABLE managed_resources (
    id              TEXT PRIMARY KEY,
    interface_id    TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    operation_id    TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    resource_kind   TEXT NOT NULL CHECK (resource_kind IN (
                        'wireguard_config','nft_up','nft_down','sysctl','systemd_enable')),
    path            TEXT,
    fingerprint     TEXT,
    created_at_ms   INTEGER NOT NULL,
    UNIQUE(interface_id, resource_kind)
);

CREATE INDEX managed_resources_operation_idx
ON managed_resources(operation_id);

UPDATE system_state
SET schema_version = 3, updated_at_ms = unixepoch('subsec') * 1000
WHERE singleton_id = 1;

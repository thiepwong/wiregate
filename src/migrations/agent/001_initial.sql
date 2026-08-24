-- File: src/migrations/agent/001_initial.sql
-- Project: WireGate
-- Copyright (c) 2026 Thiep Wong
-- SPDX-License-Identifier: MIT
-- Author: Thiep Wong
-- Email: thiep.wong@gmail.com
-- Date: 2026-08-24
-- Description: WireGate database migration.

CREATE TABLE system_state (
    singleton_id         INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    gateway_id           TEXT NOT NULL UNIQUE,
    schema_version       INTEGER NOT NULL,
    current_key_version  INTEGER NOT NULL DEFAULT 0,
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL
);

CREATE TABLE interfaces (
    id                            TEXT PRIMARY KEY,
    name                          TEXT NOT NULL UNIQUE,
    backend                       TEXT NOT NULL CHECK (backend IN (
                                      'wg_quick','runtime_only','networkmanager',
                                      'networkd','container','unknown')),
    namespace_kind                TEXT NOT NULL CHECK (namespace_kind IN ('host','external')),
    management_mode               TEXT NOT NULL CHECK (management_mode IN (
                                      'observed','adopted','managed','unsupported')),
    config_path                   TEXT,
    service_owner                 TEXT,
    service_unit                  TEXT,
    save_config_detected          INTEGER NOT NULL DEFAULT 0 CHECK (save_config_detected IN (0,1)),
    config_present               INTEGER NOT NULL DEFAULT 0 CHECK (config_present IN (0,1)),
    runtime_present              INTEGER NOT NULL DEFAULT 0 CHECK (runtime_present IN (0,1)),
    file_hash                     TEXT,
    runtime_fingerprint           TEXT,
    last_applied_revision_id      TEXT REFERENCES config_revisions(id) ON DELETE SET NULL,
    revision                      INTEGER NOT NULL DEFAULT 0,
    drift_state                   TEXT NOT NULL DEFAULT 'none' CHECK (drift_state IN (
                                      'none','file','runtime','both','secret','unknown')),
    deployment_profile            TEXT CHECK (deployment_profile IN (
                                      'server_only','lan','full_tunnel','site_to_site')),
    firewall_mode                 TEXT CHECK (firewall_mode IN ('managed_nft','external')),
    managed_firewall_backend      TEXT CHECK (managed_firewall_backend IN ('nftables','none')),
    firewall_ownership_id         TEXT,
    external_firewall_plan_hash   TEXT,
    external_firewall_attested_by TEXT,
    external_firewall_attested_at_ms INTEGER,
    last_seen_at_ms               INTEGER NOT NULL,
    created_at_ms                 INTEGER NOT NULL,
    updated_at_ms                 INTEGER NOT NULL
);

CREATE TABLE interface_addresses (
    id             TEXT PRIMARY KEY,
    interface_id   TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    family         INTEGER NOT NULL CHECK (family IN (4,6)),
    address        TEXT NOT NULL,
    prefix_length  INTEGER NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('file','runtime','managed')),
    UNIQUE(interface_id, family, address, prefix_length)
);

CREATE TABLE address_pools (
    id                 TEXT PRIMARY KEY,
    interface_id       TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    family             INTEGER NOT NULL CHECK (family IN (4,6)),
    cidr               TEXT NOT NULL,
    gateway_address    TEXT NOT NULL,
    allocation_policy  TEXT NOT NULL DEFAULT 'sequential',
    created_at_ms      INTEGER NOT NULL,
    UNIQUE(interface_id, cidr)
);

CREATE TABLE peers (
    id                         TEXT PRIMARY KEY,
    interface_id               TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    name                       TEXT NOT NULL,
    public_key                 TEXT NOT NULL,
    key_mode                   TEXT NOT NULL CHECK (key_mode IN ('managed','one_time','external')),
    lifecycle_state            TEXT NOT NULL CHECK (lifecycle_state IN (
                                        'active','disabled','pending_reenroll','revoked','archived')),
    config_revision_id         TEXT REFERENCES config_revisions(id) ON DELETE SET NULL,
    archived_block_secret_id   TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    endpoint                   TEXT,
    persistent_keepalive       INTEGER NOT NULL DEFAULT 0,
    observed_present           INTEGER NOT NULL DEFAULT 1 CHECK (observed_present IN (0,1)),
    last_seen_at_ms            INTEGER NOT NULL,
    expires_at_ms              INTEGER,
    replacement_peer_id        TEXT REFERENCES peers(id) ON DELETE SET NULL,
    created_at_ms              INTEGER NOT NULL,
    updated_at_ms              INTEGER NOT NULL,
    revoked_at_ms              INTEGER,
    UNIQUE(interface_id, public_key)
);

CREATE TABLE address_allocations (
    id                   TEXT PRIMARY KEY,
    pool_id              TEXT NOT NULL REFERENCES address_pools(id) ON DELETE CASCADE,
    peer_id              TEXT REFERENCES peers(id) ON DELETE SET NULL,
    address              TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('allocated','quarantined','released')),
    quarantine_until_ms  INTEGER,
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL,
    UNIQUE(pool_id, address)
);

CREATE TABLE peer_allowed_ips (
    id          TEXT PRIMARY KEY,
    peer_id     TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    cidr        TEXT NOT NULL,
    purpose     TEXT NOT NULL CHECK (purpose IN ('tunnel_address','routed_subnet')),
    created_at_ms INTEGER NOT NULL,
    UNIQUE(peer_id, cidr)
);

CREATE TABLE peer_runtime (
    peer_id                 TEXT PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
    endpoint                TEXT,
    latest_handshake_at_ms  INTEGER NOT NULL DEFAULT 0,
    transfer_rx_bytes       INTEGER NOT NULL DEFAULT 0,
    transfer_tx_bytes       INTEGER NOT NULL DEFAULT 0,
    runtime_seen_at_ms      INTEGER NOT NULL,
    activity_state          TEXT NOT NULL CHECK (activity_state IN ('never_seen','active','idle','unknown'))
);

CREATE TABLE client_profiles (
    id                         TEXT PRIMARY KEY,
    peer_id                    TEXT NOT NULL UNIQUE REFERENCES peers(id) ON DELETE CASCADE,
    profile_state              TEXT NOT NULL CHECK (profile_state IN (
                                    'ready','one_time_pending','consumed','external','revoked','secret_unavailable')),
    client_private_secret_id   TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    preshared_secret_id        TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    endpoint_host              TEXT,
    endpoint_port              INTEGER,
    mtu                        INTEGER,
    dns_json                   TEXT NOT NULL DEFAULT '[]',
    created_at_ms              INTEGER NOT NULL,
    updated_at_ms              INTEGER NOT NULL
);

CREATE TABLE client_routes (
    id                 TEXT PRIMARY KEY,
    client_profile_id  TEXT NOT NULL REFERENCES client_profiles(id) ON DELETE CASCADE,
    cidr               TEXT NOT NULL,
    UNIQUE(client_profile_id, cidr)
);

CREATE TABLE secret_envelopes (
    id                  TEXT PRIMARY KEY,
    owner_type          TEXT NOT NULL,
    owner_id            TEXT NOT NULL,
    purpose             TEXT NOT NULL CHECK (purpose IN (
                            'client_private_key','preshared_key','one_time_payload',
                            'archived_peer_block','snapshot_payload')),
    algorithm           TEXT NOT NULL,
    ciphertext          BLOB NOT NULL,
    payload_nonce       BLOB NOT NULL,
    wrapped_dek         BLOB NOT NULL,
    wrap_nonce          BLOB NOT NULL,
    key_version         INTEGER NOT NULL,
    aad_version         INTEGER NOT NULL,
    secret_fingerprint  BLOB,
    created_at_ms       INTEGER NOT NULL,
    updated_at_ms       INTEGER NOT NULL,
    UNIQUE(owner_type, owner_id, purpose)
);

CREATE TABLE one_time_artifacts (
    id                  TEXT PRIMARY KEY,
    peer_id             TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    secret_envelope_id  TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    token_hash          BLOB NOT NULL UNIQUE,
    state               TEXT NOT NULL CHECK (state IN ('ready','consuming','consumed','expired')),
    expires_at_ms       INTEGER NOT NULL,
    consumed_at_ms      INTEGER,
    created_at_ms       INTEGER NOT NULL,
    CHECK (
      (state IN ('ready','consuming') AND secret_envelope_id IS NOT NULL) OR
      (state IN ('consumed','expired') AND secret_envelope_id IS NULL)
    )
);

CREATE TABLE operations (
    id                    TEXT PRIMARY KEY,
    interface_id          TEXT REFERENCES interfaces(id),
    type                  TEXT NOT NULL CHECK (type IN (
                              'adopt_interface','resolve_drift','create_interface',
                              'set_interface_state','create_peer','update_peer',
                              'disable_peer','enable_peer','revoke_peer',
                              'reenroll_peer','rollback_operation')),
    state                 TEXT NOT NULL CHECK (state IN (
                              'pending','validated','snapshotted','executing','verifying',
                              'committed','rolling_back','rolled_back','rollback_failed',
                              'rejected','expired')),
    plan_version          INTEGER NOT NULL,
    intent_json           TEXT NOT NULL,
    idempotency_key       TEXT NOT NULL,
    actor_id              TEXT NOT NULL,
    actor_role            TEXT NOT NULL,
    request_id            TEXT NOT NULL,
    reason                TEXT,
    expected_revision     INTEGER,
    original_file_hash    TEXT,
    proposed_file_hash    TEXT,
    original_runtime_hash TEXT,
    proposed_diff_json    TEXT,
    snapshot_id           TEXT REFERENCES snapshots(id) ON DELETE SET NULL,
    error_code            TEXT,
    error_message_redacted TEXT,
    expires_at_ms         INTEGER,
    created_at_ms         INTEGER NOT NULL,
    updated_at_ms         INTEGER NOT NULL,
    finished_at_ms        INTEGER,
    UNIQUE(actor_id, type, idempotency_key)
);

CREATE TABLE operation_steps (
    id                    TEXT PRIMARY KEY,
    operation_id          TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    step_order            INTEGER NOT NULL,
    name                  TEXT NOT NULL,
    state                 TEXT NOT NULL CHECK (state IN (
                              'pending','executing','applied','failed','rolling_back','rolled_back')),
    effect_kind           TEXT NOT NULL CHECK (effect_kind IN (
                              'database','file','wgctrl','netlink','nftables','systemd','sysctl')),
    original_fingerprint  TEXT,
    proposed_fingerprint  TEXT,
    details_redacted_json TEXT,
    rollback_secret_id    TEXT REFERENCES secret_envelopes(id) ON DELETE SET NULL,
    started_at_ms         INTEGER,
    finished_at_ms        INTEGER,
    error_redacted        TEXT,
    UNIQUE(operation_id, step_order)
);

CREATE TABLE snapshots (
    id                   TEXT PRIMARY KEY,
    interface_id         TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    operation_id         TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    secret_envelope_id   TEXT NOT NULL REFERENCES secret_envelopes(id),
    file_hash            TEXT,
    runtime_fingerprint  TEXT,
    created_at_ms        INTEGER NOT NULL
);

CREATE TABLE config_revisions (
    id                   TEXT PRIMARY KEY,
    interface_id         TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    sequence             INTEGER NOT NULL,
    file_hash            TEXT,
    runtime_fingerprint  TEXT,
    operation_id         TEXT REFERENCES operations(id) ON DELETE SET NULL,
    created_at_ms        INTEGER NOT NULL,
    UNIQUE(interface_id, sequence)
);

CREATE TABLE audit_events (
    id                TEXT PRIMARY KEY,
    actor_type        TEXT NOT NULL CHECK (actor_type IN ('user','system')),
    actor_id          TEXT NOT NULL,
    actor_role        TEXT,
    action            TEXT NOT NULL,
    target_type       TEXT NOT NULL,
    target_id         TEXT,
    request_id        TEXT NOT NULL,
    operation_id      TEXT REFERENCES operations(id) ON DELETE SET NULL,
    before_revision   INTEGER,
    after_revision    INTEGER,
    result            TEXT NOT NULL,
    reason            TEXT,
    details_redacted  TEXT,
    created_at_ms     INTEGER NOT NULL
);

CREATE TABLE firewall_objects (
    id                  TEXT PRIMARY KEY,
    interface_id        TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    family              TEXT NOT NULL,
    table_name          TEXT NOT NULL,
    chain_name          TEXT,
    object_fingerprint  TEXT NOT NULL,
    state               TEXT NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    updated_at_ms       INTEGER NOT NULL
);

CREATE TABLE detected_firewall_owners (
    id                    TEXT PRIMARY KEY,
    owner_type            TEXT NOT NULL CHECK (owner_type IN (
                              'ufw','firewalld','docker','custom_nft',
                              'iptables_nft','iptables_legacy','unknown')),
    backend               TEXT NOT NULL CHECK (backend IN (
                              'nftables','iptables_nft','iptables_legacy','unknown')),
    active                INTEGER NOT NULL CHECK (active IN (0,1)),
    policy_fingerprint    TEXT NOT NULL,
    details_redacted_json TEXT,
    last_seen_at_ms       INTEGER NOT NULL,
    UNIQUE(owner_type, backend)
);

CREATE INDEX peers_interface_state_idx ON peers(interface_id, lifecycle_state);
CREATE INDEX operations_interface_state_idx ON operations(interface_id, state);
CREATE UNIQUE INDEX operations_one_active_interface_idx
ON operations(interface_id)
WHERE interface_id IS NOT NULL
  AND state IN ('pending','validated','snapshotted','executing','verifying','rolling_back');
CREATE INDEX audit_events_created_idx ON audit_events(created_at_ms);

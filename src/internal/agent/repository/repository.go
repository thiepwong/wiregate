package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	shareddb "github.com/wiregate-project/wiregate/internal/shared/db"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
	agentmigrations "github.com/wiregate-project/wiregate/migrations/agent"
)

const schemaVersion = 4

type Repository struct {
	database  *sql.DB
	gatewayID string
	now       func() time.Time
}

type InterfaceRecord struct {
	ID                 string
	Name               string
	Backend            string
	ManagementMode     string
	ConfigPath         string
	ServiceUnit        string
	SaveConfigDetected bool
	FileHash           string
	RuntimeFingerprint string
	Revision           int64
	DriftState         string
	RuntimePresent     bool
	ConfigPresent      bool
	Addresses          []inventory.Address
	PeerCount          int
	ListenPort         int
	PublicKey          string
	DeploymentProfile  string
	FirewallMode       string
	AutoStart          bool
	ServiceState       string
	UpdatedAt          time.Time
}

type PeerRecord struct {
	ID                  string
	InterfaceID         string
	Name                string
	PublicKey           string
	KeyMode             string
	LifecycleState      string
	Endpoint            string
	PersistentKeepalive int
	AllowedIPs          []string
	LatestHandshakeAt   time.Time
	TransferRXBytes     uint64
	TransferTXBytes     uint64
	RuntimeSeenAt       time.Time
	ActivityState       string
}

func Open(ctx context.Context, path, gatewayID string) (*Repository, error) {
	database, err := shareddb.OpenSQLite(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := shareddb.ApplyMigrations(ctx, database, agentmigrations.Files); err != nil {
		_ = database.Close()
		return nil, err
	}
	repository := &Repository{
		database:  database,
		gatewayID: gatewayID,
		now:       func() time.Time { return time.Now().UTC() },
	}
	if err := repository.initializeSystemState(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return repository, nil
}

func (r *Repository) Close() error {
	return r.database.Close()
}

func (r *Repository) SchemaVersion() int {
	return schemaVersion
}

func (r *Repository) CurrentKeyVersion(ctx context.Context) (uint32, error) {
	var version int64
	if err := r.database.QueryRowContext(ctx, `
		SELECT current_key_version FROM system_state WHERE singleton_id = 1`,
	).Scan(&version); err != nil {
		return 0, fmt.Errorf("read current key version: %w", err)
	}
	if version < 0 || version > int64(^uint32(0)) {
		return 0, errors.New("current key version is out of range")
	}
	return uint32(version), nil
}

// InitializeKeyVersion binds a fresh database to an installer-created key.
// It cannot change a non-zero version and refuses initialization after any
// envelope exists; rotations use a separate journaled workflow.
func (r *Repository) InitializeKeyVersion(ctx context.Context, version uint32) error {
	if version == 0 {
		return errors.New("key version must be positive")
	}
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current, envelopes int64
	if err := tx.QueryRowContext(ctx, `
		SELECT current_key_version FROM system_state WHERE singleton_id = 1`,
	).Scan(&current); err != nil {
		return err
	}
	if current != 0 && current != int64(version) {
		return errors.New("current key version is already initialized")
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_envelopes`).Scan(&envelopes); err != nil {
		return err
	}
	if current == 0 && envelopes != 0 {
		return errors.New("cannot initialize key version while secret envelopes exist")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE system_state SET current_key_version = ?, updated_at_ms = ?
		WHERE singleton_id = 1`, version, r.now().UnixMilli(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) ReplaceInventory(ctx context.Context, snapshot inventory.Snapshot) (inventory.PersistResult, error) {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return inventory.PersistResult{}, fmt.Errorf("begin inventory transaction: %w", err)
	}
	defer tx.Rollback()

	nowMS := snapshot.RefreshedAt.UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		UPDATE interfaces
		SET config_present = 0, runtime_present = 0, updated_at_ms = ?
		WHERE management_mode = 'observed'`, nowMS); err != nil {
		return inventory.PersistResult{}, fmt.Errorf("mark interface inventory stale: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE peers
		SET observed_present = 0
		WHERE interface_id IN (
			SELECT id FROM interfaces WHERE management_mode = 'observed'
		) AND lifecycle_state = 'active'`); err != nil {
		return inventory.PersistResult{}, fmt.Errorf("mark peer inventory stale: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM peer_runtime
		WHERE peer_id IN (
			SELECT p.id
			FROM peers p
			JOIN interfaces i ON i.id = p.interface_id
			WHERE i.management_mode = 'observed'
		)`); err != nil {
		return inventory.PersistResult{}, fmt.Errorf("clear stale peer runtime: %w", err)
	}

	peerCount := 0
	for _, item := range snapshot.Interfaces {
		interfaceID, managementMode, err := r.upsertInterface(ctx, tx, item, nowMS)
		if err != nil {
			return inventory.PersistResult{}, err
		}
		if err := r.replaceAddresses(ctx, tx, interfaceID, item.Addresses); err != nil {
			return inventory.PersistResult{}, err
		}
		for _, peer := range item.Peers {
			if managementMode == "observed" {
				if err := r.upsertPeer(ctx, tx, interfaceID, peer, nowMS); err != nil {
					return inventory.PersistResult{}, err
				}
			} else if err := r.updateManagedPeerRuntime(ctx, tx, interfaceID, peer); err != nil {
				return inventory.PersistResult{}, err
			}
			peerCount++
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE system_state SET updated_at_ms = ? WHERE singleton_id = 1`, nowMS); err != nil {
		return inventory.PersistResult{}, fmt.Errorf("update system state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return inventory.PersistResult{}, fmt.Errorf("commit inventory: %w", err)
	}
	return inventory.PersistResult{
		InterfaceCount: len(snapshot.Interfaces),
		PeerCount:      peerCount,
	}, nil
}

func (r *Repository) ListInterfaces(ctx context.Context) ([]InterfaceRecord, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT i.id, i.name, i.backend, i.management_mode,
		       COALESCE(i.config_path, ''), COALESCE(i.service_unit, ''),
		       COALESCE(i.file_hash, ''), COALESCE(i.runtime_fingerprint, ''),
		       i.save_config_detected, i.revision, i.drift_state,
		       i.runtime_present, i.config_present,
		       COALESCE(i.listen_port, 0), COALESCE(i.public_key, ''),
		       COALESCE(i.deployment_profile, ''), COALESCE(i.firewall_mode, ''),
		       i.auto_start, i.service_state,
		       i.updated_at_ms,
		       COUNT(CASE WHEN p.observed_present = 1 OR p.lifecycle_state != 'active' THEN 1 END)
		FROM interfaces i
		LEFT JOIN peers p ON p.interface_id = i.id
		GROUP BY i.id
		ORDER BY i.name`)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	defer rows.Close()

	var records []InterfaceRecord
	for rows.Next() {
		var record InterfaceRecord
		var updatedAtMS int64
		if err := rows.Scan(
			&record.ID,
			&record.Name,
			&record.Backend,
			&record.ManagementMode,
			&record.ConfigPath,
			&record.ServiceUnit,
			&record.FileHash,
			&record.RuntimeFingerprint,
			&record.SaveConfigDetected,
			&record.Revision,
			&record.DriftState,
			&record.RuntimePresent,
			&record.ConfigPresent,
			&record.ListenPort,
			&record.PublicKey,
			&record.DeploymentProfile,
			&record.FirewallMode,
			&record.AutoStart,
			&record.ServiceState,
			&updatedAtMS,
			&record.PeerCount,
		); err != nil {
			return nil, fmt.Errorf("scan interface: %w", err)
		}
		record.UpdatedAt = time.UnixMilli(updatedAtMS).UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate interfaces: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close interface rows: %w", err)
	}
	for index := range records {
		addresses, err := r.listAddresses(ctx, records[index].ID)
		if err != nil {
			return nil, err
		}
		records[index].Addresses = addresses
	}
	return records, nil
}

func (r *Repository) GetInterface(ctx context.Context, id string) (InterfaceRecord, error) {
	records, err := r.ListInterfaces(ctx)
	if err != nil {
		return InterfaceRecord{}, err
	}
	for _, record := range records {
		if record.ID == id {
			return record, nil
		}
	}
	return InterfaceRecord{}, sql.ErrNoRows
}

func (r *Repository) ListPeers(ctx context.Context, interfaceID string) ([]PeerRecord, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT p.id, p.interface_id, p.name, p.public_key, p.key_mode, p.lifecycle_state,
		       COALESCE(pr.endpoint, p.endpoint, ''), p.persistent_keepalive,
		       COALESCE(pr.latest_handshake_at_ms, 0),
		       COALESCE(pr.transfer_rx_bytes, 0),
		       COALESCE(pr.transfer_tx_bytes, 0),
		       COALESCE(pr.runtime_seen_at_ms, 0),
		       COALESCE(pr.activity_state, 'unknown')
		FROM peers p
		LEFT JOIN peer_runtime pr ON pr.peer_id = p.id
		WHERE p.interface_id = ?
		  AND (p.observed_present = 1 OR p.lifecycle_state != 'active')
		ORDER BY p.name, p.public_key`, interfaceID)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var records []PeerRecord
	for rows.Next() {
		var record PeerRecord
		var handshakeMS, seenMS int64
		if err := rows.Scan(
			&record.ID,
			&record.InterfaceID,
			&record.Name,
			&record.PublicKey,
			&record.KeyMode,
			&record.LifecycleState,
			&record.Endpoint,
			&record.PersistentKeepalive,
			&handshakeMS,
			&record.TransferRXBytes,
			&record.TransferTXBytes,
			&seenMS,
			&record.ActivityState,
		); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		if handshakeMS > 0 {
			record.LatestHandshakeAt = time.UnixMilli(handshakeMS).UTC()
		}
		if seenMS > 0 {
			record.RuntimeSeenAt = time.UnixMilli(seenMS).UTC()
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate peers: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close peer rows: %w", err)
	}
	for index := range records {
		allowedIPs, err := r.listAllowedIPs(ctx, records[index].ID)
		if err != nil {
			return nil, err
		}
		records[index].AllowedIPs = allowedIPs
	}
	return records, nil
}

func (r *Repository) initializeSystemState(ctx context.Context) error {
	nowMS := r.now().UnixMilli()
	_, err := r.database.ExecContext(ctx, `
		INSERT INTO system_state(
			singleton_id, gateway_id, schema_version, current_key_version,
			created_at_ms, updated_at_ms
		) VALUES (1, ?, ?, 0, ?, ?)
		ON CONFLICT(singleton_id) DO NOTHING`,
		r.gatewayID,
		schemaVersion,
		nowMS,
		nowMS,
	)
	if err != nil {
		return fmt.Errorf("initialize system state: %w", err)
	}

	var storedGatewayID string
	var storedSchemaVersion int
	if err := r.database.QueryRowContext(ctx, `
		SELECT gateway_id, schema_version FROM system_state WHERE singleton_id = 1`,
	).Scan(&storedGatewayID, &storedSchemaVersion); err != nil {
		return fmt.Errorf("read system state: %w", err)
	}
	if storedGatewayID != r.gatewayID {
		return fmt.Errorf("gateway_id mismatch: database belongs to a different gateway")
	}
	if storedSchemaVersion != schemaVersion {
		return fmt.Errorf("schema version mismatch: database=%d binary=%d", storedSchemaVersion, schemaVersion)
	}
	return nil
}

func (r *Repository) upsertInterface(
	ctx context.Context,
	tx *sql.Tx,
	item inventory.Interface,
	nowMS int64,
) (string, string, error) {
	if item.DriftState == "" {
		item.DriftState = "unknown"
	}
	var existingID string
	var managementMode string
	var lastFileHash, lastRuntimeHash sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT i.id, i.management_mode, cr.file_hash, cr.runtime_fingerprint
		FROM interfaces i
		LEFT JOIN config_revisions cr ON cr.id = i.last_applied_revision_id
		WHERE i.name = ?`, item.Name,
	).Scan(&existingID, &managementMode, &lastFileHash, &lastRuntimeHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("find interface %s: %w", item.Name, err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		newID, err := ids.NewV7(time.UnixMilli(nowMS))
		if err != nil {
			return "", "", err
		}
		existingID = newID
		managementMode = "observed"
	} else if managementMode != "observed" {
		item.DriftState = classifyDrift(
			item.FileHash,
			item.RuntimeFingerprint,
			lastFileHash.String,
			lastRuntimeHash.String,
		)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO interfaces(
			id, name, backend, namespace_kind, management_mode,
			config_path, service_owner, service_unit, save_config_detected,
			config_present, runtime_present, file_hash, runtime_fingerprint,
			revision, drift_state, last_seen_at_ms, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, 'host', 'observed', ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			backend = excluded.backend,
			config_path = excluded.config_path,
			service_owner = excluded.service_owner,
			service_unit = excluded.service_unit,
			save_config_detected = excluded.save_config_detected,
			config_present = excluded.config_present,
			runtime_present = excluded.runtime_present,
			file_hash = excluded.file_hash,
			runtime_fingerprint = excluded.runtime_fingerprint,
			drift_state = CASE
				WHEN interfaces.drift_state = 'secret' THEN 'secret'
				ELSE excluded.drift_state
			END,
			last_seen_at_ms = excluded.last_seen_at_ms,
			updated_at_ms = excluded.updated_at_ms`,
		existingID,
		item.Name,
		item.Backend,
		nullable(item.ConfigPath),
		serviceOwner(item),
		nullable(item.ServiceUnit),
		item.SaveConfigDetected,
		item.ConfigPresent,
		item.RuntimePresent,
		nullable(item.FileHash),
		nullable(item.RuntimeFingerprint),
		item.DriftState,
		nowMS,
		nowMS,
		nowMS,
	)
	if err != nil {
		return "", "", fmt.Errorf("upsert interface %s: %w", item.Name, err)
	}
	return existingID, managementMode, nil
}

func (r *Repository) replaceAddresses(
	ctx context.Context,
	tx *sql.Tx,
	interfaceID string,
	addresses []inventory.Address,
) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM interface_addresses
		WHERE interface_id = ? AND source IN ('file','runtime')`, interfaceID); err != nil {
		return fmt.Errorf("clear interface addresses: %w", err)
	}
	for _, address := range addresses {
		id, err := ids.NewV7(r.now())
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO interface_addresses(
				id, interface_id, family, address, prefix_length, source
			) VALUES (?, ?, ?, ?, ?, ?)`,
			id,
			interfaceID,
			address.Family,
			address.Address,
			address.PrefixLength,
			address.Source,
		); err != nil {
			return fmt.Errorf("insert interface address: %w", err)
		}
	}
	return nil
}

func (r *Repository) upsertPeer(
	ctx context.Context,
	tx *sql.Tx,
	interfaceID string,
	peer inventory.Peer,
	nowMS int64,
) error {
	var peerID string
	err := tx.QueryRowContext(ctx, `
		SELECT id FROM peers WHERE interface_id = ? AND public_key = ?`,
		interfaceID,
		peer.PublicKey,
	).Scan(&peerID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("find peer: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		peerID, err = ids.NewV7(time.UnixMilli(nowMS))
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO peers(
			id, interface_id, name, public_key, key_mode, lifecycle_state,
			endpoint, persistent_keepalive, observed_present, last_seen_at_ms,
			created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, 'external', 'active', ?, ?, 1, ?, ?, ?)
		ON CONFLICT(interface_id, public_key) DO UPDATE SET
			name = CASE
				WHEN peers.key_mode = 'external' THEN excluded.name
				ELSE peers.name
			END,
			endpoint = excluded.endpoint,
			persistent_keepalive = excluded.persistent_keepalive,
			observed_present = 1,
			last_seen_at_ms = excluded.last_seen_at_ms,
			updated_at_ms = excluded.updated_at_ms`,
		peerID,
		interfaceID,
		peer.Name,
		peer.PublicKey,
		nullable(peer.Endpoint),
		peer.PersistentKeepalive,
		nowMS,
		nowMS,
		nowMS,
	); err != nil {
		return fmt.Errorf("upsert peer: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM peer_allowed_ips WHERE peer_id = ?", peerID); err != nil {
		return fmt.Errorf("clear peer allowed IPs: %w", err)
	}
	for _, prefix := range peer.AllowedIPs {
		id, err := ids.NewV7(r.now())
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO peer_allowed_ips(id, peer_id, cidr, purpose, created_at_ms)
			VALUES (?, ?, ?, 'tunnel_address', ?)`,
			id,
			peerID,
			prefix,
			nowMS,
		); err != nil {
			return fmt.Errorf("insert peer allowed IP: %w", err)
		}
	}
	if !peer.RuntimeSeenAt.IsZero() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO peer_runtime(
				peer_id, endpoint, latest_handshake_at_ms,
				transfer_rx_bytes, transfer_tx_bytes, runtime_seen_at_ms, activity_state
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(peer_id) DO UPDATE SET
				endpoint = excluded.endpoint,
				latest_handshake_at_ms = excluded.latest_handshake_at_ms,
				transfer_rx_bytes = excluded.transfer_rx_bytes,
				transfer_tx_bytes = excluded.transfer_tx_bytes,
				runtime_seen_at_ms = excluded.runtime_seen_at_ms,
				activity_state = excluded.activity_state`,
			peerID,
			nullable(peer.Endpoint),
			unixMilliOrZero(peer.LatestHandshakeAt),
			peer.TransferRXBytes,
			peer.TransferTXBytes,
			peer.RuntimeSeenAt.UnixMilli(),
			peer.ActivityState,
		); err != nil {
			return fmt.Errorf("upsert peer runtime: %w", err)
		}
	}
	return nil
}

// updateManagedPeerRuntime refreshes metrics for an already-owned peer without
// accepting file-side configuration changes into domain metadata. File drift
// must be resolved through an explicit audited operation.
func (r *Repository) updateManagedPeerRuntime(
	ctx context.Context,
	tx *sql.Tx,
	interfaceID string,
	peer inventory.Peer,
) error {
	var peerID string
	var storedFingerprint []byte
	err := tx.QueryRowContext(ctx, `
		SELECT p.id, COALESCE(se.secret_fingerprint, X'')
		FROM peers p
		LEFT JOIN client_profiles cp ON cp.peer_id = p.id
		LEFT JOIN secret_envelopes se ON se.id = cp.preshared_secret_id
		WHERE p.interface_id = ? AND p.public_key = ?`,
		interfaceID, peer.PublicKey,
	).Scan(&peerID, &storedFingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find managed peer runtime target: %w", err)
	}
	secretDrift := false
	switch {
	case len(storedFingerprint) > 0 && !peer.PSKPresent:
		secretDrift = true
	case len(storedFingerprint) == 0 && peer.PSKPresent:
		secretDrift = true
	case len(storedFingerprint) > 0 && len(peer.PSKFingerprint) > 0:
		secretDrift = subtle.ConstantTimeCompare(storedFingerprint, peer.PSKFingerprint) != 1
	}
	if secretDrift {
		if _, err := tx.ExecContext(ctx, `
			UPDATE interfaces SET drift_state = 'secret', updated_at_ms = ?
			WHERE id = ?`, r.now().UnixMilli(), interfaceID,
		); err != nil {
			return fmt.Errorf("mark secret drift: %w", err)
		}
	}
	if peer.RuntimeSeenAt.IsZero() {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO peer_runtime(
			peer_id, endpoint, latest_handshake_at_ms,
			transfer_rx_bytes, transfer_tx_bytes, runtime_seen_at_ms, activity_state
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(peer_id) DO UPDATE SET
			endpoint = excluded.endpoint,
			latest_handshake_at_ms = excluded.latest_handshake_at_ms,
			transfer_rx_bytes = excluded.transfer_rx_bytes,
			transfer_tx_bytes = excluded.transfer_tx_bytes,
			runtime_seen_at_ms = excluded.runtime_seen_at_ms,
			activity_state = excluded.activity_state`,
		peerID,
		nullable(peer.Endpoint),
		unixMilliOrZero(peer.LatestHandshakeAt),
		peer.TransferRXBytes,
		peer.TransferTXBytes,
		peer.RuntimeSeenAt.UnixMilli(),
		peer.ActivityState,
	); err != nil {
		return fmt.Errorf("update managed peer runtime: %w", err)
	}
	return nil
}

func (r *Repository) listAddresses(ctx context.Context, interfaceID string) ([]inventory.Address, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT family, address, prefix_length, source
		FROM interface_addresses
		WHERE interface_id = ?
		ORDER BY family, address, prefix_length`, interfaceID)
	if err != nil {
		return nil, fmt.Errorf("list interface addresses: %w", err)
	}
	defer rows.Close()
	var addresses []inventory.Address
	for rows.Next() {
		var address inventory.Address
		if err := rows.Scan(&address.Family, &address.Address, &address.PrefixLength, &address.Source); err != nil {
			return nil, fmt.Errorf("scan interface address: %w", err)
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}

func (r *Repository) listAllowedIPs(ctx context.Context, peerID string) ([]string, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT cidr FROM peer_allowed_ips WHERE peer_id = ? ORDER BY cidr`, peerID)
	if err != nil {
		return nil, fmt.Errorf("list peer allowed IPs: %w", err)
	}
	defer rows.Close()
	var prefixes []string
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err != nil {
			return nil, fmt.Errorf("scan peer allowed IP: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, rows.Err()
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func serviceOwner(item inventory.Interface) any {
	if item.ServiceUnit == "" {
		return nil
	}
	return "systemd"
}

func unixMilliOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func classifyDrift(currentFile, currentRuntime, appliedFile, appliedRuntime string) string {
	if appliedFile == "" && appliedRuntime == "" {
		return "unknown"
	}
	fileChanged := currentFile != appliedFile
	runtimeChanged := currentRuntime != appliedRuntime
	switch {
	case fileChanged && runtimeChanged:
		return "both"
	case fileChanged:
		return "file"
	case runtimeChanged:
		return "runtime"
	default:
		return "none"
	}
}

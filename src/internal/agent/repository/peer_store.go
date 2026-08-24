package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/ipam"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

type AddressCandidate struct {
	PoolID  string
	Address string
	Prefix  string
}

type OwnedAllowedPrefix struct {
	PeerID string
	CIDR   string
}

type SecretInput struct {
	Context  secret.Context
	Envelope secret.Envelope
}

type OneTimeInput struct {
	ID        string
	TokenHash []byte
	ExpiresAt time.Time
	Secret    SecretInput
}

type PeerCreateInput struct {
	ID                  string
	InterfaceID         string
	Name                string
	PublicKey           string
	KeyMode             string
	AllowedIPs          []string
	ClientRoutes        []string
	DNSJSON             string
	MTU                 int
	EndpointHost        string
	EndpointPort        int
	PersistentKeepalive int
	Allocation          AddressCandidate
	ClientPrivate       *SecretInput
	PresharedKey        *SecretInput
	OneTime             *OneTimeInput
	OriginalFileHash    string
	ProposedFileHash    string
	RuntimeFingerprint  string
}

type ClientMaterial struct {
	PeerID              string
	PeerName            string
	InterfaceName       string
	KeyMode             string
	ProfileState        string
	ClientPrivate       *SecretInput
	PresharedKey        *SecretInput
	Addresses           []string
	Routes              []string
	DNSJSON             string
	MTU                 int
	EndpointHost        string
	EndpointPort        int
	PersistentKeepalive int
	ServerPublicKey     string
}

func (r *Repository) GetPeer(ctx context.Context, id string) (PeerRecord, error) {
	var interfaceID string
	if err := r.database.QueryRowContext(ctx, `SELECT interface_id FROM peers WHERE id = ?`, id).Scan(&interfaceID); err != nil {
		return PeerRecord{}, err
	}
	peers, err := r.ListPeers(ctx, interfaceID)
	if err != nil {
		return PeerRecord{}, err
	}
	for _, peer := range peers {
		if peer.ID == id {
			return peer, nil
		}
	}
	return PeerRecord{}, sql.ErrNoRows
}

func (r *Repository) NextAvailableAddress(ctx context.Context, interfaceID string) (AddressCandidate, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT id, cidr, gateway_address FROM address_pools
		WHERE interface_id = ? ORDER BY family, cidr`, interfaceID,
	)
	if err != nil {
		return AddressCandidate{}, err
	}
	type pool struct{ id, cidr, gateway string }
	var pools []pool
	for rows.Next() {
		var item pool
		if err := rows.Scan(&item.id, &item.cidr, &item.gateway); err != nil {
			_ = rows.Close()
			return AddressCandidate{}, err
		}
		pools = append(pools, item)
	}
	if err := rows.Close(); err != nil {
		return AddressCandidate{}, err
	}
	for _, item := range pools {
		prefix, err := netip.ParsePrefix(item.cidr)
		if err != nil {
			return AddressCandidate{}, err
		}
		gateway, err := netip.ParseAddr(item.gateway)
		if err != nil {
			return AddressCandidate{}, err
		}
		allocated, quarantined, err := r.poolUsage(ctx, item.id)
		if err != nil {
			return AddressCandidate{}, err
		}
		address, err := ipam.Allocate(ipam.CandidateSet{
			Pool: prefix, Gateway: gateway, Allocated: allocated, Quarantined: quarantined,
		})
		if err != nil {
			continue
		}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return AddressCandidate{
			PoolID: item.id, Address: address.String(),
			Prefix: netip.PrefixFrom(address, bits).String(),
		}, nil
	}
	return AddressCandidate{}, errors.New("address pools are exhausted or unavailable")
}

func (r *Repository) ValidateAddressCandidate(
	ctx context.Context,
	interfaceID, value string,
) (AddressCandidate, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || (prefix.Addr().Is4() && prefix.Bits() != 32) ||
		(prefix.Addr().Is6() && prefix.Bits() != 128) {
		return AddressCandidate{}, errors.New("peer tunnel address must be a /32 or /128")
	}
	rows, err := r.database.QueryContext(ctx, `
		SELECT id, cidr FROM address_pools WHERE interface_id = ?`, interfaceID,
	)
	if err != nil {
		return AddressCandidate{}, err
	}
	type candidatePool struct{ id, cidr string }
	var pools []candidatePool
	for rows.Next() {
		var poolID, cidr string
		if err := rows.Scan(&poolID, &cidr); err != nil {
			_ = rows.Close()
			return AddressCandidate{}, err
		}
		pools = append(pools, candidatePool{id: poolID, cidr: cidr})
	}
	if err := rows.Close(); err != nil {
		return AddressCandidate{}, err
	}
	// The repository intentionally uses one SQLite connection. Close the pool
	// cursor before issuing the allocation query below or the nested read can
	// wait forever for that same connection.
	for _, item := range pools {
		poolID, cidr := item.id, item.cidr
		pool, err := netip.ParsePrefix(cidr)
		if err != nil || !pool.Contains(prefix.Addr()) {
			continue
		}
		var count int
		if err := r.database.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM address_allocations
			WHERE pool_id = ? AND address = ? AND state IN ('allocated','quarantined')`,
			poolID, prefix.Addr().String(),
		).Scan(&count); err != nil {
			return AddressCandidate{}, err
		}
		if count != 0 {
			return AddressCandidate{}, errors.New("peer tunnel address is unavailable")
		}
		return AddressCandidate{PoolID: poolID, Address: prefix.Addr().String(), Prefix: prefix.String()}, nil
	}
	return AddressCandidate{}, errors.New("peer tunnel address is outside managed pools")
}

func (r *Repository) ActiveAllowedPrefixes(ctx context.Context, interfaceID string) ([]string, error) {
	owned, err := r.ActiveOwnedPrefixes(ctx, interfaceID)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(owned))
	for _, item := range owned {
		result = append(result, item.CIDR)
	}
	return result, nil
}

func (r *Repository) ActiveOwnedPrefixes(ctx context.Context, interfaceID string) ([]OwnedAllowedPrefix, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT p.id, pai.cidr
		FROM peer_allowed_ips pai
		JOIN peers p ON p.id = pai.peer_id
		WHERE p.interface_id = ? AND p.lifecycle_state = 'active'
		ORDER BY pai.cidr`, interfaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OwnedAllowedPrefix
	for rows.Next() {
		var value OwnedAllowedPrefix
		if err := rows.Scan(&value.PeerID, &value.CIDR); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *Repository) CompletePeerCreate(
	ctx context.Context,
	operationID string,
	input PeerCreateInput,
) (int64, error) {
	now := r.now()
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var state string
	var expected sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT state, expected_revision FROM operations
		WHERE id = ? AND type = 'create_peer' AND interface_id = ?`,
		operationID, input.InterfaceID,
	).Scan(&state, &expected); err != nil {
		return 0, err
	}
	if state != string(agentoperation.StateExecuting) || !expected.Valid {
		return 0, errors.New("peer operation is not executing")
	}
	var currentRevision int64
	var currentHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT revision, COALESCE(file_hash, '') FROM interfaces WHERE id = ?`, input.InterfaceID,
	).Scan(&currentRevision, &currentHash); err != nil {
		return 0, err
	}
	if currentRevision != expected.Int64 || currentHash != input.OriginalFileHash {
		return 0, errors.New("interface changed before peer metadata commit")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO peers(
			id, interface_id, name, public_key, key_mode, lifecycle_state,
			persistent_keepalive, observed_present, last_seen_at_ms, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, ?, 'active', ?, 1, ?, ?, ?)`,
		input.ID, input.InterfaceID, input.Name, input.PublicKey, input.KeyMode,
		input.PersistentKeepalive, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("insert managed peer: %w", err)
	}
	for index, value := range input.AllowedIPs {
		allowedID, err := ids.NewV7(now.Add(time.Duration(index+1) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		purpose := "routed_subnet"
		prefix, _ := netip.ParsePrefix(value)
		if (prefix.Addr().Is4() && prefix.Bits() == 32) || (prefix.Addr().Is6() && prefix.Bits() == 128) {
			purpose = "tunnel_address"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO peer_allowed_ips(id, peer_id, cidr, purpose, created_at_ms)
			VALUES (?, ?, ?, ?, ?)`,
			allowedID, input.ID, value, purpose, now.UnixMilli(),
		); err != nil {
			return 0, err
		}
	}
	allocationID, err := ids.NewV7(now.Add(50 * time.Nanosecond))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO address_allocations(
			id, pool_id, peer_id, address, state, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, 'allocated', ?, ?)`,
		allocationID, input.Allocation.PoolID, input.ID, input.Allocation.Address,
		now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("allocate peer address: %w", err)
	}
	var clientSecretID, pskSecretID any
	if input.ClientPrivate != nil {
		id, err := ids.NewV7(now.Add(60 * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if err := insertEnvelope(ctx, tx, id, input.ClientPrivate.Context, input.ClientPrivate.Envelope, now); err != nil {
			return 0, err
		}
		clientSecretID = id
	}
	if input.PresharedKey != nil {
		id, err := ids.NewV7(now.Add(61 * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if err := insertEnvelope(ctx, tx, id, input.PresharedKey.Context, input.PresharedKey.Envelope, now); err != nil {
			return 0, err
		}
		pskSecretID = id
	}
	profileID, err := ids.NewV7(now.Add(70 * time.Nanosecond))
	if err != nil {
		return 0, err
	}
	profileState := "external"
	if input.KeyMode == "managed" {
		profileState = "ready"
	} else if input.KeyMode == "one_time" {
		profileState = "one_time_pending"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO client_profiles(
			id, peer_id, profile_state, client_private_secret_id,
			preshared_secret_id, endpoint_host, endpoint_port, mtu,
			dns_json, created_at_ms, updated_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profileID, input.ID, profileState, clientSecretID, pskSecretID,
		nullable(input.EndpointHost), input.EndpointPort, nullableInt(input.MTU),
		input.DNSJSON, now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return 0, fmt.Errorf("insert client profile: %w", err)
	}
	for index, route := range input.ClientRoutes {
		routeID, err := ids.NewV7(now.Add(time.Duration(index+80) * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO client_routes(id, client_profile_id, cidr) VALUES (?, ?, ?)`,
			routeID, profileID, route,
		); err != nil {
			return 0, err
		}
	}
	if input.OneTime != nil {
		if len(input.OneTime.TokenHash) != 32 || !input.OneTime.ExpiresAt.After(now) {
			return 0, errors.New("invalid one-time artifact")
		}
		envelopeID, err := ids.NewV7(now.Add(90 * time.Nanosecond))
		if err != nil {
			return 0, err
		}
		if err := insertEnvelope(ctx, tx, envelopeID, input.OneTime.Secret.Context, input.OneTime.Secret.Envelope, now); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO one_time_artifacts(
				id, peer_id, secret_envelope_id, token_hash, state, expires_at_ms, created_at_ms
			) VALUES (?, ?, ?, ?, 'ready', ?, ?)`,
			input.OneTime.ID, input.ID, envelopeID, input.OneTime.TokenHash,
			input.OneTime.ExpiresAt.UnixMilli(), now.UnixMilli(),
		); err != nil {
			return 0, err
		}
	}
	nextRevision := currentRevision + 1
	revisionID, err := ids.NewV7(now.Add(100 * time.Nanosecond))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO config_revisions(
			id, interface_id, sequence, file_hash, runtime_fingerprint,
			operation_id, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		revisionID, input.InterfaceID, nextRevision, input.ProposedFileHash,
		nullable(input.RuntimeFingerprint), operationID, now.UnixMilli(),
	); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE interfaces SET file_hash = ?, runtime_fingerprint = ?,
		    revision = ?, last_applied_revision_id = ?, drift_state = 'none',
		    updated_at_ms = ?
		WHERE id = ? AND revision = ? AND file_hash = ?`,
		input.ProposedFileHash, nullable(input.RuntimeFingerprint), nextRevision,
		revisionID, now.UnixMilli(), input.InterfaceID, currentRevision, currentHash,
	)
	if err != nil {
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, errors.New("interface revision changed while creating peer")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operations SET proposed_file_hash = ?, state = 'verifying', updated_at_ms = ?
		WHERE id = ? AND state = 'executing'`,
		input.ProposedFileHash, now.UnixMilli(), operationID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextRevision, nil
}

func (r *Repository) ClientMaterial(ctx context.Context, peerID string) (ClientMaterial, error) {
	tx, err := r.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ClientMaterial{}, err
	}
	defer tx.Rollback()
	var result ClientMaterial
	var clientSecretID, pskSecretID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT p.id, p.name, p.key_mode, p.persistent_keepalive,
		       cp.profile_state, cp.client_private_secret_id, cp.preshared_secret_id,
		       COALESCE(cp.endpoint_host, ''), COALESCE(cp.endpoint_port, 0),
		       COALESCE(cp.mtu, 0), cp.dns_json, COALESCE(i.public_key, ''), i.name
		FROM peers p
		JOIN client_profiles cp ON cp.peer_id = p.id
		JOIN interfaces i ON i.id = p.interface_id
		WHERE p.id = ?`, peerID,
	).Scan(
		&result.PeerID, &result.PeerName, &result.KeyMode,
		&result.PersistentKeepalive, &result.ProfileState,
		&clientSecretID, &pskSecretID, &result.EndpointHost,
		&result.EndpointPort, &result.MTU, &result.DNSJSON, &result.ServerPublicKey,
		&result.InterfaceName,
	); err != nil {
		return ClientMaterial{}, err
	}
	addressRows, err := tx.QueryContext(ctx, `
		SELECT cidr FROM peer_allowed_ips
		WHERE peer_id = ? AND purpose = 'tunnel_address' ORDER BY cidr`, peerID,
	)
	if err != nil {
		return ClientMaterial{}, err
	}
	for addressRows.Next() {
		var value string
		if err := addressRows.Scan(&value); err != nil {
			_ = addressRows.Close()
			return ClientMaterial{}, err
		}
		result.Addresses = append(result.Addresses, value)
	}
	_ = addressRows.Close()
	routeRows, err := tx.QueryContext(ctx, `
		SELECT cidr FROM client_routes WHERE client_profile_id = (
			SELECT id FROM client_profiles WHERE peer_id = ?
		) ORDER BY cidr`, peerID,
	)
	if err != nil {
		return ClientMaterial{}, err
	}
	for routeRows.Next() {
		var value string
		if err := routeRows.Scan(&value); err != nil {
			_ = routeRows.Close()
			return ClientMaterial{}, err
		}
		result.Routes = append(result.Routes, value)
	}
	_ = routeRows.Close()
	if clientSecretID.Valid {
		secretContext, envelope, err := loadEnvelope(ctx, tx, clientSecretID.String)
		if err != nil {
			return ClientMaterial{}, err
		}
		result.ClientPrivate = &SecretInput{Context: secretContext, Envelope: envelope}
	}
	if pskSecretID.Valid {
		secretContext, envelope, err := loadEnvelope(ctx, tx, pskSecretID.String)
		if err != nil {
			return ClientMaterial{}, err
		}
		result.PresharedKey = &SecretInput{Context: secretContext, Envelope: envelope}
	}
	return result, tx.Commit()
}

func (r *Repository) ArchivedPeerBlock(ctx context.Context, peerID string) (SecretInput, error) {
	tx, err := r.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SecretInput{}, err
	}
	defer tx.Rollback()
	var envelopeID string
	if err := tx.QueryRowContext(ctx, `
		SELECT archived_block_secret_id
		FROM peers
		WHERE id = ? AND lifecycle_state = 'disabled'`, peerID,
	).Scan(&envelopeID); err != nil {
		return SecretInput{}, err
	}
	secretContext, envelope, err := loadEnvelope(ctx, tx, envelopeID)
	if err != nil {
		return SecretInput{}, err
	}
	if secretContext.OwnerType != "peer" || secretContext.OwnerID != peerID ||
		secretContext.Purpose != "archived_peer_block" {
		return SecretInput{}, errors.New("archived peer block ownership mismatch")
	}
	if err := tx.Commit(); err != nil {
		return SecretInput{}, err
	}
	return SecretInput{Context: secretContext, Envelope: envelope}, nil
}

func (r *Repository) poolUsage(
	ctx context.Context,
	poolID string,
) (map[netip.Addr]struct{}, map[netip.Addr]struct{}, error) {
	rows, err := r.database.QueryContext(ctx, `
		SELECT address, state FROM address_allocations
		WHERE pool_id = ? AND state IN ('allocated','quarantined')`, poolID,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	allocated := make(map[netip.Addr]struct{})
	quarantined := make(map[netip.Addr]struct{})
	for rows.Next() {
		var value, state string
		if err := rows.Scan(&value, &state); err != nil {
			return nil, nil, err
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, nil, err
		}
		if state == "allocated" {
			allocated[address] = struct{}{}
		} else {
			quarantined[address] = struct{}{}
		}
	}
	return allocated, quarantined, rows.Err()
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

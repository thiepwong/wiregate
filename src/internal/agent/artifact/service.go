package artifact

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/secret"
)

var ErrUnavailable = errors.New("artifact not found")

type Record struct {
	ID        string
	PeerID    string
	Context   secret.Context
	Envelope  secret.Envelope
	ExpiresAt time.Time
}

type Store interface {
	CreateOneTime(context.Context, string, secret.Context, secret.Envelope, []byte, time.Time) (string, error)
	BeginOneTimeConsume(context.Context, []byte, time.Time) (Record, error)
	FinalizeOneTimeConsume(context.Context, string, time.Time) error
	CleanupOneTime(context.Context, time.Time) error
}

type MasterKeyFunc func(uint32) ([]byte, error)

type Service struct {
	store      Store
	masterKey  MasterKeyFunc
	keyVersion uint32
	now        func() time.Time
}

func NewService(store Store, masterKey MasterKeyFunc, keyVersion uint32) (*Service, error) {
	if store == nil || masterKey == nil || keyVersion == 0 {
		return nil, errors.New("artifact store, master key loader and key version are required")
	}
	return &Service{
		store: store, masterKey: masterKey, keyVersion: keyVersion,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// Create encrypts an artifact before persistence. The returned token is the
// only plaintext capability and must be delivered in an authenticated response
// body, never a URL.
func (s *Service) Create(
	ctx context.Context,
	peerID string,
	secretContext secret.Context,
	payload []byte,
	ttl time.Duration,
) (artifactID string, token []byte, err error) {
	if peerID == "" || ttl <= 0 {
		return "", nil, errors.New("peer ID and positive TTL are required")
	}
	master, err := s.masterKey(s.keyVersion)
	if err != nil {
		return "", nil, err
	}
	defer wipe(master)
	envelope, err := secret.Seal(master, s.keyVersion, secretContext, payload, nil)
	if err != nil {
		return "", nil, err
	}
	token = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, token); err != nil {
		return "", nil, fmt.Errorf("generate one-time token: %w", err)
	}
	artifactID, err = s.store.CreateOneTime(
		ctx, peerID, secretContext, envelope, secret.TokenHash(token), s.now().Add(ttl),
	)
	if err != nil {
		wipe(token)
		return "", nil, err
	}
	return artifactID, token, nil
}

// Consume atomically marks an artifact consuming before decrypting. Its
// finalizer runs for successful, failed and canceled consumers, so no retry
// path can return the same secret twice.
func (s *Service) Consume(ctx context.Context, token []byte, consumer func([]byte) error) (err error) {
	if len(token) != 32 || consumer == nil {
		return ErrUnavailable
	}
	record, err := s.store.BeginOneTimeConsume(ctx, secret.TokenHash(token), s.now())
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		finalizeErr := s.store.FinalizeOneTimeConsume(finalizeContext, record.ID, s.now())
		if err == nil && finalizeErr != nil {
			err = finalizeErr
		}
	}()
	master, err := s.masterKey(record.Envelope.KeyVersion)
	if err != nil {
		return err
	}
	defer wipe(master)
	plaintext, err := secret.Open(master, record.Context, record.Envelope)
	if err != nil {
		return err
	}
	defer wipe(plaintext)
	return consumer(plaintext)
}

func (s *Service) Recover(ctx context.Context) error {
	return s.store.CleanupOneTime(ctx, s.now())
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

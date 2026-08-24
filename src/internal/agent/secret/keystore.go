package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type KeyStore struct {
	root string
}

func NewKeyStore(root string) (*KeyStore, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("key directory must be an absolute path")
	}
	return &KeyStore{root: filepath.Clean(root)}, nil
}

func (s *KeyStore) LoadMaster(version uint32) ([]byte, error) {
	if version == 0 {
		return nil, errors.New("key version must be positive")
	}
	return readKeyFile(filepath.Join(s.root, fmt.Sprintf("key-v%04d.bin", version)))
}

func (s *KeyStore) LoadFingerprint() ([]byte, error) {
	return readKeyFile(filepath.Join(s.root, "fingerprint.key"))
}

func (s *KeyStore) CreateMaster(version uint32) ([]byte, error) {
	if version == 0 {
		return nil, errors.New("key version must be positive")
	}
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	return createKeyFile(filepath.Join(s.root, fmt.Sprintf("key-v%04d.bin", version)))
}

func (s *KeyStore) CreateFingerprint() ([]byte, error) {
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	return createKeyFile(filepath.Join(s.root, "fingerprint.key"))
}

// Initialize creates the first KEK and independent fingerprint key. It is
// intended for an explicit installer/CLI action, never normal agent startup.
func (s *KeyStore) Initialize() (master, fingerprint []byte, err error) {
	if err := s.ensureDirectory(); err != nil {
		return nil, nil, err
	}
	fingerprintPath := filepath.Join(s.root, "fingerprint.key")
	fingerprint, err = createKeyFile(fingerprintPath)
	if err != nil {
		return nil, nil, err
	}
	master, err = createKeyFile(filepath.Join(s.root, "key-v0001.bin"))
	if err != nil {
		wipe(fingerprint)
		if removeErr := os.Remove(fingerprintPath); removeErr != nil {
			return nil, nil, errors.Join(err, fmt.Errorf("clean partial fingerprint key: %w", removeErr))
		}
		return nil, nil, err
	}
	return master, fingerprint, nil
}

func (s *KeyStore) ensureDirectory() error {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("inspect key directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("key path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("key directory permissions must not allow group/world access: %o", info.Mode().Perm())
	}
	return nil
}

func createKeyFile(path string) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		wipe(key)
		return nil, fmt.Errorf("create key file: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		wipe(key)
		return nil, fmt.Errorf("write key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		wipe(key)
		return nil, fmt.Errorf("sync key file: %w", err)
	}
	if err := file.Close(); err != nil {
		wipe(key)
		return nil, fmt.Errorf("close key file: %w", err)
	}
	return key, nil
}

func readKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("key file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file permissions must not allow group/world access: %o", info.Mode().Perm())
	}
	if info.Size() != keySize {
		return nil, fmt.Errorf("key file must contain exactly %d bytes", keySize)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return body, nil
}

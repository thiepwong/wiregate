// File: src/internal/agent/adapters/filesystem/config.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package filesystem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wiregate-project/wiregate/internal/agent/validation"
)

const MaxConfigBytes = 4 << 20

var (
	ErrRevisionConflict  = errors.New("config revision conflict")
	ErrAtomicUnsupported = errors.New("required atomic rename operation is unsupported")
)

type ConfigFile struct {
	Path string
	Body []byte
	Hash string
	Mode fs.FileMode
	UID  int
	GID  int
}

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("WireGuard config root must be an absolute path")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect config root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("WireGuard config root must be a real directory")
	}
	return &Store{root: root}, nil
}

func (s *Store) ReadConfig(interfaceName string) (ConfigFile, error) {
	if err := validation.InterfaceName(interfaceName); err != nil {
		return ConfigFile{}, err
	}
	path := filepath.Join(s.root, interfaceName+".conf")
	if filepath.Dir(path) != s.root {
		return ConfigFile{}, errors.New("config path escaped root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ConfigFile{}, fmt.Errorf("inspect config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ConfigFile{}, errors.New("config must be a regular non-symlink file")
	}
	if info.Size() > MaxConfigBytes {
		return ConfigFile{}, fmt.Errorf("config exceeds %d bytes", MaxConfigBytes)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return ConfigFile{}, fmt.Errorf("open config without following links: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return ConfigFile{}, fmt.Errorf("read config: %w", err)
	}
	if len(body) > MaxConfigBytes {
		return ConfigFile{}, fmt.Errorf("config exceeded %d bytes while reading", MaxConfigBytes)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return ConfigFile{}, fmt.Errorf("inspect opened config: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return ConfigFile{}, ErrRevisionConflict
	}
	uid, gid := ownership(openedInfo)
	return ConfigFile{
		Path: path, Body: body, Hash: SHA256(body),
		Mode: openedInfo.Mode().Perm(), UID: uid, GID: gid,
	}, nil
}

// ExchangeConfig stages and atomically exchanges an adopted config. The
// displaced file is hashed after exchange, closing the editor/CLI race between
// the initial read and rename. A mismatch is exchanged back when safe.
func (s *Store) ExchangeConfig(interfaceName, expectedHash string, proposed []byte) ([]byte, error) {
	if len(proposed) > MaxConfigBytes {
		return nil, fmt.Errorf("proposed config exceeds %d bytes", MaxConfigBytes)
	}
	current, err := s.ReadConfig(interfaceName)
	if err != nil {
		return nil, err
	}
	if current.Hash != expectedHash {
		return nil, ErrRevisionConflict
	}
	staged, err := os.CreateTemp(s.root, ".wiregate-stage-*")
	if err != nil {
		return nil, fmt.Errorf("create staged config: %w", err)
	}
	stagePath := staged.Name()
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.Remove(stagePath)
		}
	}()
	if err := staged.Chmod(current.Mode); err != nil {
		_ = staged.Close()
		return nil, fmt.Errorf("preserve staged mode: %w", err)
	}
	if current.UID >= 0 && current.GID >= 0 {
		if err := staged.Chown(current.UID, current.GID); err != nil {
			_ = staged.Close()
			return nil, fmt.Errorf("preserve staged ownership: %w", err)
		}
	}
	if _, err := staged.Write(proposed); err != nil {
		_ = staged.Close()
		return nil, fmt.Errorf("write staged config: %w", err)
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return nil, fmt.Errorf("sync staged config: %w", err)
	}
	if err := staged.Close(); err != nil {
		return nil, fmt.Errorf("close staged config: %w", err)
	}

	if err := renameExchange(stagePath, current.Path); err != nil {
		if errors.Is(err, ErrAtomicUnsupported) {
			return nil, err
		}
		return nil, fmt.Errorf("atomic config exchange: %w", err)
	}
	displaced, readErr := readRegular(stagePath)
	if readErr != nil || SHA256(displaced) != expectedHash {
		swapBackErr := renameExchange(stagePath, current.Path)
		if swapBackErr != nil {
			keepStage = true
			return nil, fmt.Errorf(
				"%w: displaced file mismatch and swap-back failed; conflict evidence retained at %s",
				ErrRevisionConflict, stagePath,
			)
		}
		if err := syncDirectory(s.root); err != nil {
			return nil, fmt.Errorf("%w: restored destination but directory sync failed", ErrRevisionConflict)
		}
		return nil, ErrRevisionConflict
	}
	destination, err := readRegular(current.Path)
	if err != nil || SHA256(destination) != SHA256(proposed) {
		if swapBackErr := renameExchange(stagePath, current.Path); swapBackErr != nil {
			keepStage = true
			return nil, fmt.Errorf("verify destination failed and rollback failed; evidence retained at %s", stagePath)
		}
		return nil, errors.New("verify exchanged config failed")
	}
	if err := syncDirectory(s.root); err != nil {
		if swapBackErr := renameExchange(stagePath, current.Path); swapBackErr != nil {
			keepStage = true
			return nil, fmt.Errorf("sync config directory failed and rollback failed; evidence retained at %s", stagePath)
		}
		return nil, fmt.Errorf("sync config directory: %w", err)
	}
	return displaced, nil
}

func (s *Store) CreateConfig(interfaceName string, body []byte, mode fs.FileMode) error {
	if err := validation.InterfaceName(interfaceName); err != nil {
		return err
	}
	if len(body) > MaxConfigBytes {
		return fmt.Errorf("config exceeds %d bytes", MaxConfigBytes)
	}
	path := filepath.Join(s.root, interfaceName+".conf")
	staged, err := os.CreateTemp(s.root, ".wiregate-new-*")
	if err != nil {
		return err
	}
	stagePath := staged.Name()
	defer os.Remove(stagePath)
	if mode == 0 {
		mode = 0o600
	}
	if err := staged.Chmod(mode); err != nil {
		_ = staged.Close()
		return err
	}
	if _, err := staged.Write(body); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := renameNoReplace(stagePath, path); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

func (s *Store) SupportsAtomicExchange() error {
	left, err := os.CreateTemp(s.root, ".wiregate-exchange-left-*")
	if err != nil {
		return err
	}
	leftPath := left.Name()
	_ = left.Close()
	defer os.Remove(leftPath)
	right, err := os.CreateTemp(s.root, ".wiregate-exchange-right-*")
	if err != nil {
		return err
	}
	rightPath := right.Name()
	_ = right.Close()
	defer os.Remove(rightPath)
	if err := renameExchange(leftPath, rightPath); err != nil {
		return err
	}
	return renameExchange(leftPath, rightPath)
}

func SHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular non-symlink file")
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

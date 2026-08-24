// File: src/internal/agent/transport/unix.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

type UnixListener struct {
	net.Listener
	path       string
	ownsSocket bool
}

func ListenUnix(path string, mode os.FileMode, socketGID, allowedUID, allowedGID int, logger *slog.Logger) (*UnixListener, error) {
	if listener, ok, err := systemdListener(); err != nil {
		return nil, err
	} else if ok {
		return &UnixListener{
			Listener:   &credentialListener{Listener: listener, allowedUID: allowedUID, allowedGID: allowedGID, logger: logger},
			path:       path,
			ownsSocket: false,
		}, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod Unix socket: %w", err)
	}
	if socketGID >= 0 {
		if err := os.Chown(path, -1, socketGID); err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("chown Unix socket group: %w", err)
		}
	}
	return &UnixListener{
		Listener: &credentialListener{
			Listener:   listener,
			allowedUID: allowedUID,
			allowedGID: allowedGID,
			logger:     logger,
		},
		path:       path,
		ownsSocket: true,
	}, nil
}

func (l *UnixListener) Close() error {
	err := l.Listener.Close()
	if l.ownsSocket {
		if removeErr := os.Remove(l.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(err, removeErr)
		}
	}
	return err
}

type credentialListener struct {
	net.Listener
	allowedUID int
	allowedGID int
	logger     *slog.Logger
}

func (l *credentialListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, gid, err := peerCredentials(connection)
		if err == nil && (l.allowedUID < 0 || uid == l.allowedUID) && (l.allowedGID < 0 || gid == l.allowedGID) {
			return connection, nil
		}
		_ = connection.Close()
		l.logger.Warn("rejected Unix socket peer", "uid", uid, "gid", gid, "error", err)
	}
}

func systemdListener() (net.Listener, bool, error) {
	listenPID, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || listenPID != os.Getpid() {
		return nil, false, nil
	}
	listenFDs, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || listenFDs < 1 {
		return nil, false, nil
	}
	file := os.NewFile(uintptr(3), "systemd-agent-socket")
	if file == nil {
		return nil, false, errors.New("systemd socket fd 3 is unavailable")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, false, fmt.Errorf("use systemd socket: %w", err)
	}
	return listener, true, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect existing socket: %w", err)
	case info.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale Unix socket: %w", err)
	}
	return nil
}

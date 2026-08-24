//go:build linux

// File: src/internal/agent/transport/peercred_linux.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(connection net.Conn) (int, int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return -1, -1, fmt.Errorf("expected Unix connection, got %T", connection)
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return -1, -1, fmt.Errorf("get raw Unix connection: %w", err)
	}

	var uid, gid int
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		uid = int(credentials.Uid)
		gid = int(credentials.Gid)
	}); err != nil {
		return -1, -1, fmt.Errorf("inspect Unix peer: %w", err)
	}
	if credentialErr != nil {
		return -1, -1, fmt.Errorf("read SO_PEERCRED: %w", credentialErr)
	}
	return uid, gid, nil
}

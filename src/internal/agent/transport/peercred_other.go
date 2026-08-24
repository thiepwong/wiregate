//go:build !linux

// File: src/internal/agent/transport/peercred_other.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package transport

import "net"

func peerCredentials(net.Conn) (int, int, error) {
	// Production is Linux-only. Development on other platforms must configure
	// allowed_peer_uid/gid=-1; filesystem socket permissions remain enforced.
	return -1, -1, nil
}

// File: src/internal/agent/transport/notify.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package transport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// NotifySystemd sends a state datagram when the process was launched under a
// Type=notify service. An unset NOTIFY_SOCKET is not an error.
func NotifySystemd(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if strings.ContainsAny(state, "\x00") || state == "" {
		return errors.New("invalid systemd notification state")
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + strings.TrimPrefix(socket, "@")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connect systemd notify socket: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(state)); err != nil {
		return fmt.Errorf("send systemd notification: %w", err)
	}
	return nil
}

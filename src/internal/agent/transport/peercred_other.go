//go:build !linux

package transport

import "net"

func peerCredentials(net.Conn) (int, int, error) {
	// Production is Linux-only. Development on other platforms must configure
	// allowed_peer_uid/gid=-1; filesystem socket permissions remain enforced.
	return -1, -1, nil
}

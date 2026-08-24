//go:build linux

package wgctrl

import (
	"context"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func ApplyPeer(ctx context.Context, interfaceName string, spec PeerSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	peer, err := BuildPeerConfig(spec)
	if err != nil {
		return err
	}
	return configureOne(interfaceName, peer)
}

func RemovePeer(ctx context.Context, interfaceName, publicKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	peer, err := BuildRemovePeer(publicKey)
	if err != nil {
		return err
	}
	return configureOne(interfaceName, peer)
}

func configureOne(interfaceName string, peer wgtypes.PeerConfig) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl: %w", err)
	}
	defer client.Close()
	if err := client.ConfigureDevice(interfaceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}); err != nil {
		return fmt.Errorf("configure target WireGuard peer: %w", err)
	}
	return nil
}

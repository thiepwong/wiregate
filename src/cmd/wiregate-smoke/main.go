// File: src/cmd/wiregate-smoke/main.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

// Command wiregate-smoke exercises the privileged agent contract in a Linux
// lab. It is intentionally excluded from release bundles and must run as the
// configured web UID so Unix peer-credential authorization is still enforced.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var socket, output string
	var removeInterface bool
	flag.StringVar(&socket, "socket", "/run/wiregate/agent.sock", "agent Unix socket")
	flag.StringVar(&output, "config-output", "", "optional exclusive 0600 path for the temporary client config")
	flag.BoolVar(&removeInterface, "remove-interface", false, "remove the managed test interface after verification")
	flag.Parse()
	if err := run(socket, output, removeInterface); err != nil {
		fmt.Fprintln(os.Stderr, "smoke failed:", err)
		os.Exit(1)
	}
}

func run(socket, output string, removeInterface bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///wiregate-agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return err
	}
	defer connection.Close()
	client := wiregatev1.NewWireGateAgentServiceClient(connection)
	info, err := client.GetAgentInfo(ctx, &wiregatev1.GetAgentInfoRequest{})
	if err != nil {
		return err
	}
	fmt.Printf("agent ready: version=%s schema=%d read_only=%t\n",
		info.GetAgent().GetVersion(), info.GetAgent().GetSchemaVersion(), info.GetAgent().GetReadOnly())

	interfaces, err := client.ListInterfaces(ctx, &wiregatev1.ListInterfacesRequest{})
	if err != nil {
		return err
	}
	var target *wiregatev1.InterfaceView
	for _, item := range interfaces.GetInterfaces() {
		if item.GetName() == "wg0" {
			target = item
		}
	}
	if target == nil {
		key := fmt.Sprintf("smoke-interface-%d", time.Now().UnixNano())
		plan, err := client.PreviewCreateInterface(ctx, &wiregatev1.PreviewCreateInterfaceRequest{
			Context: mutation("interface:create", key, nil), Name: "wg0",
			InterfaceAddresses: []string{"10.200.0.1/24"}, ListenPort: 51820,
			DeploymentProfile: "server_only", FirewallMode: "external", AutoStart: true,
		})
		if err != nil {
			return fmt.Errorf("preview interface: %w", err)
		}
		result, err := client.CreateInterface(ctx, &wiregatev1.CommitOperationRequest{
			OperationId: plan.GetOperationId(), Context: mutation("interface:create", key, nil),
		})
		if err != nil {
			return fmt.Errorf("create interface: %w", err)
		}
		target = &wiregatev1.InterfaceView{Id: plan.GetOperationId(), Name: "wg0", Revision: result.GetInterfaceRevision(), ListenPort: 51820}
		fmt.Printf("created interface wg0 revision=%d\n", target.GetRevision())
	}

	peers, err := client.ListPeers(ctx, &wiregatev1.ListPeersRequest{InterfaceId: target.GetId()})
	if err != nil {
		return err
	}
	var peer *wiregatev1.PeerView
	for _, item := range peers.GetPeers() {
		if item.GetName() == "smoke-client" && item.GetLifecycleState() != "revoked" {
			peer = item
		}
	}
	revision := target.GetRevision()
	if peer == nil {
		key := fmt.Sprintf("smoke-peer-%d", time.Now().UnixNano())
		plan, err := client.PreviewCreatePeer(ctx, &wiregatev1.PreviewCreatePeerRequest{
			Context: mutation("client:manage", key, &revision), InterfaceId: target.GetId(),
			Name: "smoke-client", KeyMode: "managed", ClientRoutes: []string{"10.200.0.0/24"},
			EndpointHost: text("192.168.252.2"), EndpointPort: number(51820),
			PersistentKeepaliveSeconds: number(25), UsePresharedKey: true,
		})
		if err != nil {
			return fmt.Errorf("preview peer: %w", err)
		}
		created, err := client.CreatePeer(ctx, &wiregatev1.CommitOperationRequest{
			OperationId: plan.GetOperationId(), Context: mutation("client:manage", key, nil),
		})
		if err != nil {
			return fmt.Errorf("create peer: %w", err)
		}
		peer = created.GetPeer()
		revision = created.GetOperation().GetInterfaceRevision()
		fmt.Printf("created managed peer revision=%d\n", revision)
	}

	config, err := export(ctx, client, peer.GetId(), wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_WIREGUARD_CONF)
	if err != nil {
		return fmt.Errorf("export config: %w", err)
	}
	defer clear(config)
	qr, err := export(ctx, client, peer.GetId(), wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_QR_PNG)
	if err != nil {
		return fmt.Errorf("export QR: %w", err)
	}
	if len(qr) < 8 || string(qr[:8]) != "\x89PNG\r\n\x1a\n" {
		return errors.New("QR export is not a PNG")
	}
	clear(qr)
	fmt.Println("managed config and QR export verified")
	if output != "" {
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := file.Write(config); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}

	if peer.GetLifecycleState() == "active" {
		revision, err = lifecycle(ctx, client, peer.GetId(), "disable", revision)
		if err != nil {
			return err
		}
		fmt.Printf("disabled peer revision=%d\n", revision)
	}
	revision, err = lifecycle(ctx, client, peer.GetId(), "enable", revision)
	if err != nil {
		return err
	}
	fmt.Printf("re-enabled peer revision=%d\n", revision)
	if removeInterface {
		key := fmt.Sprintf("smoke-remove-interface-%d", time.Now().UnixNano())
		plan, err := client.PreviewSetInterfaceState(ctx, &wiregatev1.PreviewSetInterfaceStateRequest{
			Context: mutation("interface:manage", key, &revision), InterfaceId: target.GetId(),
			DesiredState: "removed",
		})
		if err != nil {
			return fmt.Errorf("preview interface removal: %w", err)
		}
		if _, err := client.SetInterfaceState(ctx, &wiregatev1.CommitOperationRequest{
			OperationId: plan.GetOperationId(), Context: mutation("interface:manage", key, nil),
		}); err != nil {
			return fmt.Errorf("remove interface: %w", err)
		}
		remaining, err := client.ListInterfaces(ctx, &wiregatev1.ListInterfacesRequest{})
		if err != nil {
			return err
		}
		for _, item := range remaining.GetInterfaces() {
			if item.GetId() == target.GetId() {
				return errors.New("removed interface remains in inventory")
			}
		}
		fmt.Println("managed interface removal verified")
	}
	fmt.Println("smoke contract passed")
	return nil
}

func lifecycle(ctx context.Context, client wiregatev1.WireGateAgentServiceClient, peerID, action string, revision int64) (int64, error) {
	key := fmt.Sprintf("smoke-%s-%d", action, time.Now().UnixNano())
	plan, err := client.PreviewPeerMutation(ctx, &wiregatev1.PreviewPeerMutationRequest{
		Context: mutation("client:manage", key, &revision), PeerId: peerID, Mutation: action,
	})
	if err != nil {
		return revision, fmt.Errorf("preview %s: %w", action, err)
	}
	request := &wiregatev1.CommitOperationRequest{OperationId: plan.GetOperationId(), Context: mutation("client:manage", key, nil)}
	var result *wiregatev1.OperationRef
	switch action {
	case "disable":
		result, err = client.DisablePeer(ctx, request)
	case "enable":
		result, err = client.EnablePeer(ctx, request)
	default:
		return revision, errors.New("unsupported lifecycle action")
	}
	if err != nil {
		return revision, fmt.Errorf("commit %s: %w", action, err)
	}
	return result.GetInterfaceRevision(), nil
}

func export(ctx context.Context, client wiregatev1.WireGateAgentServiceClient, peerID string, format wiregatev1.ArtifactFormat) ([]byte, error) {
	stream, err := client.ExportClientArtifact(ctx, &wiregatev1.ExportClientArtifactRequest{
		Actor:  &wiregatev1.ActorContext{ActorId: "lab-smoke", ActorRole: "admin", RequestId: fmt.Sprintf("request-%d", time.Now().UnixNano()), Permission: "client:export-secret"},
		PeerId: peerID, Format: format, IdempotencyKey: fmt.Sprintf("export-%d", time.Now().UnixNano()),
	})
	if err != nil {
		return nil, err
	}
	var result []byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			clear(result)
			return nil, err
		}
		result = append(result, chunk.GetData()...)
	}
}

func mutation(permission, key string, revision *int64) *wiregatev1.MutationContext {
	reason := "WireGate Linux lab smoke test"
	return &wiregatev1.MutationContext{
		Actor:          &wiregatev1.ActorContext{ActorId: "lab-smoke", ActorRole: "admin", RequestId: fmt.Sprintf("request-%d", time.Now().UnixNano()), Permission: permission},
		IdempotencyKey: key, ExpectedRevision: revision, Reason: &reason,
	}
}

func text(value string) *string   { return &value }
func number(value uint32) *uint32 { return &value }

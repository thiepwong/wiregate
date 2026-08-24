// Command wiregate-adopt-smoke validates the adopt-only control path against
// an existing wg-quick interface. It is a lab tool and is not shipped in the
// release bundle.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var socket, interfaceName, endpointHost string
	flag.StringVar(&socket, "socket", "/run/wiregate/agent.sock", "agent Unix socket")
	flag.StringVar(&interfaceName, "interface", "wg-existing", "existing wg-quick interface")
	flag.StringVar(&endpointHost, "endpoint-host", "127.0.0.1", "server endpoint in generated client profiles")
	flag.Parse()
	if err := run(socket, interfaceName, endpointHost); err != nil {
		fmt.Fprintln(os.Stderr, "adopt smoke failed:", err)
		os.Exit(1)
	}
}

func run(socket, interfaceName, endpointHost string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	fmt.Printf("agent version=%s schema=%d\n", info.GetAgent().GetVersion(), info.GetAgent().GetSchemaVersion())

	target, err := findInterface(ctx, client, interfaceName)
	if err != nil {
		return err
	}
	if target.GetManagementMode() == wiregatev1.ManagementMode_MANAGEMENT_MODE_OBSERVED {
		revision := target.GetRevision()
		key := unique("adopt")
		preview, err := client.PreviewAdoption(ctx, &wiregatev1.PreviewAdoptionRequest{
			Context: mutation("interface:adopt", key, &revision), InterfaceId: target.GetId(),
		})
		if err != nil {
			return fmt.Errorf("preview adoption: %w", err)
		}
		result, err := client.CommitAdoption(ctx, &wiregatev1.CommitOperationRequest{
			OperationId: preview.GetOperationId(), Context: mutation("interface:adopt", key, nil),
		})
		if err != nil {
			return fmt.Errorf("commit adoption: %w", err)
		}
		fmt.Printf("adopted %s revision=%d plan=%s\n", interfaceName, result.GetInterfaceRevision(), preview.GetTextualDiffRedacted())
		target, err = findInterface(ctx, client, interfaceName)
		if err != nil {
			return err
		}
	}
	if target.GetManagementMode() != wiregatev1.ManagementMode_MANAGEMENT_MODE_ADOPTED {
		return fmt.Errorf("interface mode is %s, want adopted", target.GetManagementMode())
	}

	peersResponse, err := client.ListPeers(ctx, &wiregatev1.ListPeersRequest{InterfaceId: target.GetId()})
	if err != nil {
		return err
	}
	var oldPeers []*wiregatev1.PeerView
	for _, peer := range peersResponse.GetPeers() {
		if peer.GetKeyMode() == "external" && peer.GetLifecycleState() != "revoked" {
			oldPeers = append(oldPeers, peer)
		}
	}
	if len(oldPeers) < 2 {
		return fmt.Errorf("expected two imported external peers, got %d", len(oldPeers))
	}
	revision := target.GetRevision()
	for _, peer := range oldPeers[:2] {
		if peer.GetLifecycleState() == "disabled" {
			revision, err = lifecycle(ctx, client, peer.GetId(), "enable", revision)
			if err != nil {
				return err
			}
		}
	}
	newName := fmt.Sprintf("adopted-existing-%d", time.Now().Unix()%100000)
	updateKey := unique("update")
	updatePlan, err := client.PreviewUpdatePeer(ctx, &wiregatev1.PreviewUpdatePeerRequest{
		Context: mutation("client:manage", updateKey, &revision),
		PeerId:  oldPeers[0].GetId(), Name: &newName,
	})
	if err != nil {
		return fmt.Errorf("preview imported peer update: %w", err)
	}
	updated, err := client.UpdatePeer(ctx, &wiregatev1.CommitOperationRequest{
		OperationId: updatePlan.GetOperationId(), Context: mutation("client:manage", updateKey, nil),
	})
	if err != nil {
		return fmt.Errorf("commit imported peer update: %w", err)
	}
	revision = updated.GetInterfaceRevision()
	fmt.Printf("updated imported peer revision=%d\n", revision)

	for _, peer := range oldPeers[:2] {
		revision, err = lifecycle(ctx, client, peer.GetId(), "disable", revision)
		if err != nil {
			return err
		}
		revision, err = lifecycle(ctx, client, peer.GetId(), "enable", revision)
		if err != nil {
			return err
		}
	}
	fmt.Printf("disabled and re-enabled two imported peers revision=%d\n", revision)

	createKey := unique("create")
	createPlan, err := client.PreviewCreatePeer(ctx, &wiregatev1.PreviewCreatePeerRequest{
		Context: mutation("client:manage", createKey, &revision), InterfaceId: target.GetId(),
		Name: "adopt-smoke-new-peer", KeyMode: "managed",
		ClientRoutes: []string{"10.88.0.0/24"}, EndpointHost: text(endpointHost),
		EndpointPort: number(51888), PersistentKeepaliveSeconds: number(25),
		UsePresharedKey: true,
	})
	if err != nil {
		return fmt.Errorf("preview new peer on adopted interface: %w", err)
	}
	created, err := client.CreatePeer(ctx, &wiregatev1.CommitOperationRequest{
		OperationId: createPlan.GetOperationId(), Context: mutation("client:manage", createKey, nil),
	})
	if err != nil {
		return fmt.Errorf("create new peer on adopted interface: %w", err)
	}
	if created.GetPeer() == nil || created.GetPeer().GetKeyMode() != "managed" {
		return errors.New("created peer response is incomplete")
	}
	fmt.Printf("created new managed peer allowed_ips=%v revision=%d\nadopt-only contract passed\n",
		created.GetPeer().GetAllowedIps(), created.GetOperation().GetInterfaceRevision())
	return nil
}

func findInterface(
	ctx context.Context,
	client wiregatev1.WireGateAgentServiceClient,
	name string,
) (*wiregatev1.InterfaceView, error) {
	response, err := client.ListInterfaces(ctx, &wiregatev1.ListInterfacesRequest{})
	if err != nil {
		return nil, err
	}
	for _, item := range response.GetInterfaces() {
		if item.GetName() == name {
			return item, nil
		}
	}
	return nil, fmt.Errorf("interface %s was not discovered", name)
}

func lifecycle(
	ctx context.Context,
	client wiregatev1.WireGateAgentServiceClient,
	peerID, action string,
	revision int64,
) (int64, error) {
	key := unique(action)
	plan, err := client.PreviewPeerMutation(ctx, &wiregatev1.PreviewPeerMutationRequest{
		Context: mutation("client:manage", key, &revision), PeerId: peerID, Mutation: action,
	})
	if err != nil {
		return revision, fmt.Errorf("preview %s imported peer: %w", action, err)
	}
	request := &wiregatev1.CommitOperationRequest{
		OperationId: plan.GetOperationId(), Context: mutation("client:manage", key, nil),
	}
	var result *wiregatev1.OperationRef
	if action == "disable" {
		result, err = client.DisablePeer(ctx, request)
	} else {
		result, err = client.EnablePeer(ctx, request)
	}
	if err != nil {
		return revision, fmt.Errorf("commit %s imported peer: %w", action, err)
	}
	return result.GetInterfaceRevision(), nil
}

func mutation(permission, key string, revision *int64) *wiregatev1.MutationContext {
	reason := "WireGate adopt-only Linux lab smoke test"
	return &wiregatev1.MutationContext{
		Actor: &wiregatev1.ActorContext{
			ActorId: "lab-adopt-smoke", ActorRole: "admin",
			RequestId: unique("request"), Permission: permission,
		},
		IdempotencyKey: key, ExpectedRevision: revision, Reason: &reason,
	}
}

func unique(prefix string) string { return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()) }
func text(value string) *string   { return &value }
func number(value uint32) *uint32 { return &value }

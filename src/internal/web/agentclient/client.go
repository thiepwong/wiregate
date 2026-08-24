package agentclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	connection *grpc.ClientConn
	api        wiregatev1.WireGateAgentServiceClient
}

type Artifact struct {
	Data        []byte
	ContentType string
	Filename    string
}

func New(socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("agent socket path is required")
	}
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		dial := net.Dialer{Timeout: 3 * time.Second}
		return dial.DialContext(ctx, "unix", socketPath)
	}
	connection, err := grpc.NewClient(
		"passthrough:///wiregate-agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4<<20),
			grpc.MaxCallSendMsgSize(4<<20),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create agent client: %w", err)
	}
	return &Client{
		connection: connection,
		api:        wiregatev1.NewWireGateAgentServiceClient(connection),
	}, nil
}

func (c *Client) Close() error {
	return c.connection.Close()
}

func (c *Client) GetAgentInfo(ctx context.Context) (*wiregatev1.GetAgentInfoResponse, error) {
	return c.api.GetAgentInfo(ctx, &wiregatev1.GetAgentInfoRequest{})
}

func (c *Client) ListInterfaces(ctx context.Context) (*wiregatev1.ListInterfacesResponse, error) {
	return c.api.ListInterfaces(ctx, &wiregatev1.ListInterfacesRequest{})
}

func (c *Client) GetInterface(ctx context.Context, id string) (*wiregatev1.GetInterfaceResponse, error) {
	return c.api.GetInterface(ctx, &wiregatev1.GetInterfaceRequest{InterfaceId: id})
}

func (c *Client) ListPeers(ctx context.Context, interfaceID string) (*wiregatev1.ListPeersResponse, error) {
	return c.api.ListPeers(ctx, &wiregatev1.ListPeersRequest{InterfaceId: interfaceID})
}

func (c *Client) GetDiagnostics(ctx context.Context) (*wiregatev1.GetDiagnosticsResponse, error) {
	return c.api.GetDiagnostics(ctx, &wiregatev1.GetDiagnosticsRequest{})
}

func (c *Client) PreviewAdoption(
	ctx context.Context,
	request *wiregatev1.PreviewAdoptionRequest,
) (*wiregatev1.OperationPlan, error) {
	return c.api.PreviewAdoption(ctx, request)
}

func (c *Client) CommitAdoption(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	return c.api.CommitAdoption(ctx, request)
}

func (c *Client) PreviewCreateInterface(
	ctx context.Context,
	request *wiregatev1.PreviewCreateInterfaceRequest,
) (*wiregatev1.OperationPlan, error) {
	return c.api.PreviewCreateInterface(ctx, request)
}

func (c *Client) CreateInterface(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	return c.api.CreateInterface(ctx, request)
}

func (c *Client) PreviewCreatePeer(
	ctx context.Context,
	request *wiregatev1.PreviewCreatePeerRequest,
) (*wiregatev1.OperationPlan, error) {
	return c.api.PreviewCreatePeer(ctx, request)
}

func (c *Client) CreatePeer(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.CreatePeerResponse, error) {
	return c.api.CreatePeer(ctx, request)
}

func (c *Client) PreviewUpdatePeer(
	ctx context.Context,
	request *wiregatev1.PreviewUpdatePeerRequest,
) (*wiregatev1.OperationPlan, error) {
	return c.api.PreviewUpdatePeer(ctx, request)
}

func (c *Client) UpdatePeer(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	return c.api.UpdatePeer(ctx, request)
}

func (c *Client) PreviewPeerMutation(
	ctx context.Context,
	request *wiregatev1.PreviewPeerMutationRequest,
) (*wiregatev1.OperationPlan, error) {
	return c.api.PreviewPeerMutation(ctx, request)
}

func (c *Client) DisablePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return c.api.DisablePeer(ctx, request)
}

func (c *Client) EnablePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return c.api.EnablePeer(ctx, request)
}

func (c *Client) RevokePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return c.api.RevokePeer(ctx, request)
}

func (c *Client) ExportClientArtifact(
	ctx context.Context,
	request *wiregatev1.ExportClientArtifactRequest,
) (Artifact, error) {
	stream, err := c.api.ExportClientArtifact(ctx, request)
	if err != nil {
		return Artifact{}, err
	}
	return collectArtifact(stream.Recv)
}

func (c *Client) ConsumeOneTimeArtifact(
	ctx context.Context,
	request *wiregatev1.ConsumeOneTimeArtifactRequest,
) (Artifact, error) {
	stream, err := c.api.ConsumeOneTimeArtifact(ctx, request)
	if err != nil {
		return Artifact{}, err
	}
	return collectArtifact(stream.Recv)
}

func collectArtifact(recv func() (*wiregatev1.ArtifactChunk, error)) (Artifact, error) {
	var result Artifact
	for {
		chunk, err := recv()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			clear(result.Data)
			return Artifact{}, err
		}
		if len(result.Data)+len(chunk.GetData()) > 2<<20 {
			clear(result.Data)
			return Artifact{}, fmt.Errorf("agent artifact exceeds size limit")
		}
		if result.ContentType == "" {
			result.ContentType = chunk.GetContentType()
			result.Filename = chunk.GetFilename()
		}
		result.Data = append(result.Data, chunk.GetData()...)
	}
}

func (c *Client) GetOperation(
	ctx context.Context,
	operationID string,
) (*wiregatev1.GetOperationResponse, error) {
	return c.api.GetOperation(ctx, &wiregatev1.GetOperationRequest{OperationId: operationID})
}

func (c *Client) ListOperations(
	ctx context.Context,
	request *wiregatev1.ListOperationsRequest,
) (*wiregatev1.ListOperationsResponse, error) {
	return c.api.ListOperations(ctx, request)
}

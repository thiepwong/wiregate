// File: src/internal/agent/rpc/server.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package rpc

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"github.com/wiregate-project/wiregate/internal/agent/adoption"
	"github.com/wiregate-project/wiregate/internal/agent/artifact"
	"github.com/wiregate-project/wiregate/internal/agent/control"
	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	agentoperation "github.com/wiregate-project/wiregate/internal/agent/operation"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/shared/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	wiregatev1.UnimplementedWireGateAgentServiceServer

	repository *repository.Repository
	inventory  *inventory.Service
	gatewayID  string
	hostname   string
	startedAt  time.Time
	adoption   *adoption.Service
	artifacts  *artifact.Service
	control    *control.Service
}

func NewServer(
	repository *repository.Repository,
	inventoryService *inventory.Service,
	gatewayID string,
	adoptionService ...*adoption.Service,
) *Server {
	hostname, _ := os.Hostname()
	server := &Server{
		repository: repository,
		inventory:  inventoryService,
		gatewayID:  gatewayID,
		hostname:   hostname,
		startedAt:  time.Now().UTC(),
	}
	if len(adoptionService) > 0 {
		server.adoption = adoptionService[0]
	}
	return server
}

// EnableArtifacts wires secret-bearing RPCs only after the key store and
// artifact recovery have completed successfully. A nil service keeps those
// RPCs fail-closed.
func (s *Server) EnableArtifacts(service *artifact.Service) {
	s.artifacts = service
}

func (s *Server) EnableControl(service *control.Service) {
	s.control = service
}

func (s *Server) PreviewCreateInterface(
	ctx context.Context,
	request *wiregatev1.PreviewCreateInterfaceRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "interface control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	preview, err := s.control.PreviewCreateInterface(ctx, control.InterfaceRequest{
		Name: request.GetName(), Addresses: request.GetInterfaceAddresses(),
		ListenPort:        uint16(request.GetListenPort()),
		DeploymentProfile: request.GetDeploymentProfile(),
		FirewallMode:      request.GetFirewallMode(), LANCIDRs: request.GetLanCidrs(),
		EgressDevice: request.GetEgressDevice(), AutoStart: request.GetAutoStart(),
	}, controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	issues := make([]*wiregatev1.ValidationIssue, 0, len(preview.Issues))
	for _, issue := range preview.Issues {
		issues = append(issues, &wiregatev1.ValidationIssue{
			Code: issue.Code, Severity: issue.Severity, Field: issue.Field,
			Summary: issue.Summary, Remediation: issue.Remediation,
		})
	}
	return &wiregatev1.OperationPlan{
		OperationId: preview.OperationID, OperationType: preview.OperationType,
		BaseRevision: preview.BaseRevision, SemanticDiffJson: preview.SemanticDiffJSON,
		TextualDiffRedacted: preview.TextualDiffRedacted, Issues: issues,
		Disruptive: preview.Disruptive, ExpiresAtMs: preview.ExpiresAt.UnixMilli(),
	}, nil
}

func (s *Server) CreateInterface(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "interface control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.control.CommitCreateInterface(
		ctx, request.GetOperationId(), controlActor(mutation),
	)
	if err != nil {
		return nil, controlError(err)
	}
	return &wiregatev1.OperationRef{
		OperationId: result.OperationID, State: string(result.State),
		InterfaceRevision:    result.InterfaceRevision,
		EffectiveOnNextStart: result.EffectiveNextBoot,
	}, nil
}

func (s *Server) PreviewSetInterfaceState(
	ctx context.Context,
	request *wiregatev1.PreviewSetInterfaceStateRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "interface control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil || mutation.ExpectedRevision == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor and expected revision are required")
	}
	preview, err := s.control.PreviewSetInterfaceState(
		ctx, request.GetInterfaceId(), request.GetDesiredState(),
		mutation.GetExpectedRevision(), controlActor(mutation),
	)
	if err != nil {
		return nil, controlError(err)
	}
	return operationPlanMessage(preview), nil
}

func (s *Server) SetInterfaceState(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "interface control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.control.CommitSetInterfaceState(
		ctx, request.GetOperationId(), controlActor(mutation),
	)
	if err != nil {
		return nil, controlError(err)
	}
	return &wiregatev1.OperationRef{
		OperationId: result.OperationID, State: string(result.State),
		InterfaceRevision: result.InterfaceRevision,
	}, nil
}

func (s *Server) PreviewCreatePeer(
	ctx context.Context,
	request *wiregatev1.PreviewCreatePeerRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil || mutation.ExpectedRevision == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor and expected revision are required")
	}
	preview, err := s.control.PreviewCreatePeer(ctx, control.PeerRequest{
		InterfaceID: request.GetInterfaceId(), Name: request.GetName(),
		KeyMode: request.GetKeyMode(), ExternalPublicKey: request.GetExternalPublicKey(),
		ServerAllowedIPs: request.GetServerAllowedIps(), ClientRoutes: request.GetClientRoutes(),
		DNS: request.GetDns(), MTU: uint16(request.GetMtu()),
		EndpointHost: request.GetEndpointHost(), EndpointPort: uint16(request.GetEndpointPort()),
		PersistentKeepalive: uint16(request.GetPersistentKeepaliveSeconds()),
		UsePresharedKey:     request.GetUsePresharedKey(),
	}, mutation.GetExpectedRevision(), controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	return operationPlanMessage(preview), nil
}

func (s *Server) CreatePeer(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.CreatePeerResponse, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.control.CommitCreatePeer(ctx, request.GetOperationId(), controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	peer, err := s.repository.GetPeer(ctx, result.PeerID)
	if err != nil {
		return nil, internalError(err)
	}
	response := &wiregatev1.CreatePeerResponse{
		Operation: &wiregatev1.OperationRef{
			OperationId: result.OperationID, State: string(result.State),
			InterfaceRevision:    result.InterfaceRevision,
			EffectiveOnNextStart: result.EffectiveNextBoot,
		},
		Peer: peerMessage(peer),
	}
	if result.OneTimeArtifactID != "" {
		response.OneTimeArtifactId = &result.OneTimeArtifactID
		response.OneTimeToken = append([]byte(nil), result.OneTimeToken...)
	}
	return response, nil
}

func (s *Server) PreviewUpdatePeer(
	ctx context.Context,
	request *wiregatev1.PreviewUpdatePeerRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil || mutation.ExpectedRevision == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor and expected revision are required")
	}
	var name, endpoint *string
	var keepalive *uint16
	if request.Name != nil {
		value := request.GetName()
		name = &value
	}
	if request.Endpoint != nil {
		value := request.GetEndpoint()
		endpoint = &value
	}
	if request.PersistentKeepaliveSeconds != nil {
		value := uint16(request.GetPersistentKeepaliveSeconds())
		keepalive = &value
	}
	preview, err := s.control.PreviewUpdatePeer(ctx, control.PeerUpdateRequest{
		PeerID: request.GetPeerId(), Name: name,
		ServerAllowedIPs: request.GetServerAllowedIps(), ClientRoutes: request.GetClientRoutes(),
		Endpoint: endpoint, PersistentKeepalive: keepalive,
	}, mutation.GetExpectedRevision(), controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	return operationPlanMessage(preview), nil
}

func (s *Server) UpdatePeer(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.control.CommitUpdatePeer(ctx, request.GetOperationId(), controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	return &wiregatev1.OperationRef{
		OperationId: result.OperationID, State: string(result.State),
		InterfaceRevision:    result.InterfaceRevision,
		EffectiveOnNextStart: result.EffectiveNextBoot,
	}, nil
}

func (s *Server) PreviewPeerMutation(
	ctx context.Context,
	request *wiregatev1.PreviewPeerMutationRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil || mutation.ExpectedRevision == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor and expected revision are required")
	}
	preview, err := s.control.PreviewPeerLifecycle(ctx, request.GetPeerId(), request.GetMutation(),
		mutation.GetExpectedRevision(), controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	return operationPlanMessage(preview), nil
}

func (s *Server) DisablePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return s.commitPeerLifecycle(ctx, request, "disable")
}

func (s *Server) EnablePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return s.commitPeerLifecycle(ctx, request, "enable")
}

func (s *Server) RevokePeer(ctx context.Context, request *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return s.commitPeerLifecycle(ctx, request, "revoke")
}

func (s *Server) commitPeerLifecycle(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
	mutationName string,
) (*wiregatev1.OperationRef, error) {
	if s.control == nil {
		return nil, status.Error(codes.FailedPrecondition, "peer control is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.control.CommitPeerLifecycle(ctx, request.GetOperationId(), mutationName, controlActor(mutation))
	if err != nil {
		return nil, controlError(err)
	}
	return &wiregatev1.OperationRef{
		OperationId: result.OperationID, State: string(result.State),
		InterfaceRevision:    result.InterfaceRevision,
		EffectiveOnNextStart: result.EffectiveNextBoot,
	}, nil
}

func operationPlanMessage(preview control.Preview) *wiregatev1.OperationPlan {
	issues := make([]*wiregatev1.ValidationIssue, 0, len(preview.Issues))
	for _, issue := range preview.Issues {
		issues = append(issues, &wiregatev1.ValidationIssue{
			Code: issue.Code, Severity: issue.Severity, Field: issue.Field,
			Summary: issue.Summary, Remediation: issue.Remediation,
		})
	}
	return &wiregatev1.OperationPlan{
		OperationId: preview.OperationID, OperationType: preview.OperationType,
		BaseRevision: preview.BaseRevision, SemanticDiffJson: preview.SemanticDiffJSON,
		TextualDiffRedacted: preview.TextualDiffRedacted, Issues: issues,
		Disruptive: preview.Disruptive, ExpiresAtMs: preview.ExpiresAt.UnixMilli(),
	}
}

func (s *Server) PreviewAdoption(
	ctx context.Context,
	request *wiregatev1.PreviewAdoptionRequest,
) (*wiregatev1.OperationPlan, error) {
	if s.adoption == nil {
		return nil, status.Error(codes.FailedPrecondition, "secret key or atomic filesystem support is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil || mutation.ExpectedRevision == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor and expected revision are required")
	}
	preview, err := s.adoption.Preview(
		ctx,
		request.GetInterfaceId(),
		mutation.GetExpectedRevision(),
		adoptionActor(mutation),
	)
	if err != nil {
		return nil, adoptionError(err)
	}
	issues := make([]*wiregatev1.ValidationIssue, 0, len(preview.Warnings))
	for _, warning := range preview.Warnings {
		issues = append(issues, &wiregatev1.ValidationIssue{
			Code: warning.Code, Severity: "warning", Summary: warning.Message,
		})
	}
	semanticDiff, _ := json.Marshal(map[string]any{
		"management_mode": map[string]string{"before": "observed", "after": "adopted"},
		"config_rewrite":  false, "existing_peers": preview.PeerCount,
		"address_pools":       preview.PoolCIDRs,
		"address_allocations": preview.AllocationCount,
	})
	return &wiregatev1.OperationPlan{
		OperationId: preview.OperationID, OperationType: "adopt_interface",
		BaseFileHash: preview.BaseFileHash, BaseRevision: preview.BaseRevision,
		Issues: issues, SemanticDiffJson: string(semanticDiff),
		TextualDiffRedacted: preview.TextualDiffRedacted,
		Disruptive:          false, ExpiresAtMs: preview.ExpiresAt.UnixMilli(),
	}, nil
}

func (s *Server) CommitAdoption(
	ctx context.Context,
	request *wiregatev1.CommitOperationRequest,
) (*wiregatev1.OperationRef, error) {
	if s.adoption == nil {
		return nil, status.Error(codes.FailedPrecondition, "adoption is unavailable")
	}
	mutation := request.GetContext()
	if mutation == nil || mutation.Actor == nil {
		return nil, status.Error(codes.InvalidArgument, "mutation actor is required")
	}
	result, err := s.adoption.Commit(ctx, request.GetOperationId(), adoptionActor(mutation))
	if err != nil {
		return nil, adoptionError(err)
	}
	return &wiregatev1.OperationRef{
		OperationId: result.OperationID, State: string(result.State),
		InterfaceRevision: result.InterfaceRevision,
	}, nil
}

func NewGRPCServer(logger *slog.Logger) *grpc.Server {
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(4<<20),
		grpc.MaxSendMsgSize(4<<20),
		grpc.UnaryInterceptor(unaryInterceptor(logger)),
		grpc.StreamInterceptor(streamInterceptor(logger)),
	)
}

func (s *Server) GetAgentInfo(context.Context, *wiregatev1.GetAgentInfoRequest) (*wiregatev1.GetAgentInfoResponse, error) {
	return &wiregatev1.GetAgentInfoResponse{
		Agent: &wiregatev1.AgentInfo{
			Version:       version.Version,
			GatewayId:     s.gatewayID,
			Hostname:      s.hostname,
			Platform:      runtime.GOOS + "/" + runtime.GOARCH,
			SchemaVersion: int32(s.repository.SchemaVersion()),
			ReadOnly:      s.adoption == nil && s.control == nil,
			StartedAtMs:   s.startedAt.UnixMilli(),
		},
	}, nil
}

func (s *Server) ListInterfaces(ctx context.Context, _ *wiregatev1.ListInterfacesRequest) (*wiregatev1.ListInterfacesResponse, error) {
	records, err := s.repository.ListInterfaces(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	response := &wiregatev1.ListInterfacesResponse{Interfaces: make([]*wiregatev1.InterfaceView, 0, len(records))}
	for _, record := range records {
		response.Interfaces = append(response.Interfaces, interfaceMessage(record))
	}
	return response, nil
}

func (s *Server) GetInterface(ctx context.Context, request *wiregatev1.GetInterfaceRequest) (*wiregatev1.GetInterfaceResponse, error) {
	if request.GetInterfaceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "interface_id is required")
	}
	record, err := s.repository.GetInterface(ctx, request.GetInterfaceId())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "interface not found")
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &wiregatev1.GetInterfaceResponse{Interface: interfaceMessage(record)}, nil
}

func (s *Server) ListPeers(ctx context.Context, request *wiregatev1.ListPeersRequest) (*wiregatev1.ListPeersResponse, error) {
	if request.GetInterfaceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "interface_id is required")
	}
	records, err := s.repository.ListPeers(ctx, request.GetInterfaceId())
	if err != nil {
		return nil, internalError(err)
	}
	response := &wiregatev1.ListPeersResponse{Peers: make([]*wiregatev1.PeerView, 0, len(records))}
	for _, record := range records {
		response.Peers = append(response.Peers, peerMessage(record))
	}
	return response, nil
}

func (s *Server) RefreshInventory(ctx context.Context, _ *wiregatev1.RefreshInventoryRequest) (*wiregatev1.RefreshInventoryResponse, error) {
	result, err := s.inventory.Refresh(ctx)
	if err != nil {
		return nil, internalError(err)
	}
	return &wiregatev1.RefreshInventoryResponse{
		InterfaceCount: int32(result.InterfaceCount),
		PeerCount:      int32(result.PeerCount),
		RefreshedAtMs:  time.Now().UTC().UnixMilli(),
	}, nil
}

func (s *Server) GetDiagnostics(_ context.Context, _ *wiregatev1.GetDiagnosticsRequest) (*wiregatev1.GetDiagnosticsResponse, error) {
	diagnostics := s.inventory.Diagnostics()
	issues := make([]*wiregatev1.DiagnosticIssue, 0, len(diagnostics.Issues))
	for _, issue := range diagnostics.Issues {
		issues = append(issues, &wiregatev1.DiagnosticIssue{
			Code:        issue.Code,
			Severity:    issue.Severity,
			Summary:     issue.Summary,
			Remediation: issue.Remediation,
		})
	}
	lastError := firstError(
		diagnostics.ConfigSource.Error,
		diagnostics.RuntimeSource.Error,
		diagnostics.AddressSource.Error,
	)
	return &wiregatev1.GetDiagnosticsResponse{
		Diagnostics: &wiregatev1.DiagnosticsView{
			DatabaseReady:      true,
			ConfigRootReady:    diagnostics.ConfigSource.Ready,
			RuntimeSourceReady: diagnostics.RuntimeSource.Ready,
			AddressSourceReady: diagnostics.AddressSource.Ready,
			LastRefreshAtMs:    timeToMillis(diagnostics.RefreshedAt),
			LastRefreshError:   lastError,
			Issues:             issues,
		},
	}, nil
}

func (s *Server) ConsumeOneTimeArtifact(
	request *wiregatev1.ConsumeOneTimeArtifactRequest,
	stream grpc.ServerStreamingServer[wiregatev1.ArtifactChunk],
) error {
	if s.artifacts == nil {
		return status.Error(codes.FailedPrecondition, "one-time artifact service is unavailable")
	}
	if err := validateArtifactActor(request.GetActor()); err != nil {
		return err
	}
	if request.GetFormat() != wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_WIREGUARD_CONF &&
		request.GetFormat() != wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_QR_PNG {
		return status.Error(codes.InvalidArgument, "unsupported artifact format")
	}
	if len(request.GetToken()) != 32 {
		return status.Error(codes.NotFound, "artifact unavailable")
	}
	err := s.artifacts.Consume(stream.Context(), request.GetToken(), func(payload []byte) error {
		body, contentType, filename, convertErr := artifactPayload(payload, request.GetFormat(), "wireguard-client")
		if convertErr != nil {
			return convertErr
		}
		defer clear(body)
		return streamArtifact(body, contentType, filename, stream.Send)
	})
	if errors.Is(err, artifact.ErrUnavailable) {
		return status.Error(codes.NotFound, "artifact unavailable")
	}
	if err != nil {
		return internalError(err)
	}
	return nil
}

func (s *Server) ExportClientArtifact(
	request *wiregatev1.ExportClientArtifactRequest,
	stream grpc.ServerStreamingServer[wiregatev1.ArtifactChunk],
) error {
	if s.control == nil {
		return status.Error(codes.FailedPrecondition, "client export is unavailable")
	}
	if err := validateArtifactActor(request.GetActor()); err != nil {
		return err
	}
	if request.GetPeerId() == "" || request.GetIdempotencyKey() == "" {
		return status.Error(codes.InvalidArgument, "peer and idempotency key are required")
	}
	if request.GetFormat() != wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_WIREGUARD_CONF &&
		request.GetFormat() != wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_QR_PNG {
		return status.Error(codes.InvalidArgument, "unsupported artifact format")
	}
	actor := request.GetActor()
	config, name, err := s.control.ExportClientConfig(stream.Context(), request.GetPeerId(), control.Actor{
		ID: actor.GetActorId(), Role: actor.GetActorRole(), RequestID: actor.GetRequestId(),
		Permission: actor.GetPermission(), IdempotencyKey: request.GetIdempotencyKey(),
	})
	if err != nil {
		return controlError(err)
	}
	defer clear(config)
	body, contentType, filename, err := artifactPayload(config, request.GetFormat(), name)
	if err != nil {
		return internalError(err)
	}
	defer clear(body)
	if err := streamArtifact(body, contentType, filename, stream.Send); err != nil {
		return err
	}
	return nil
}

func artifactPayload(
	config []byte,
	format wiregatev1.ArtifactFormat,
	name string,
) ([]byte, string, string, error) {
	if format == wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_QR_PNG {
		body, err := qrcode.Encode(string(config), qrcode.Medium, 384)
		return body, "image/png", name + ".png", err
	}
	return append([]byte(nil), config...), "text/plain; charset=utf-8", name + ".conf", nil
}

func streamArtifact(
	payload []byte,
	contentType, filename string,
	send func(*wiregatev1.ArtifactChunk) error,
) error {
	const chunkSize = 32 << 10
	if len(payload) == 0 {
		return send(&wiregatev1.ArtifactChunk{ContentType: contentType, Filename: filename})
	}
	for offset := 0; offset < len(payload); offset += chunkSize {
		end := min(offset+chunkSize, len(payload))
		chunk := &wiregatev1.ArtifactChunk{Data: append([]byte(nil), payload[offset:end]...)}
		if offset == 0 {
			chunk.ContentType = contentType
			chunk.Filename = filename
		}
		if err := send(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetOperation(
	ctx context.Context,
	request *wiregatev1.GetOperationRequest,
) (*wiregatev1.GetOperationResponse, error) {
	if strings.TrimSpace(request.GetOperationId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id is required")
	}
	record, err := s.repository.GetOperation(ctx, request.GetOperationId())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "operation not found")
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &wiregatev1.GetOperationResponse{Operation: operationMessage(record)}, nil
}

func (s *Server) ListOperations(
	ctx context.Context,
	request *wiregatev1.ListOperationsRequest,
) (*wiregatev1.ListOperationsResponse, error) {
	pageSize := int(request.GetPageSize())
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize < 1 || pageSize > 200 {
		return nil, status.Error(codes.InvalidArgument, "page_size must be between 1 and 200")
	}
	before, beforeID, err := decodeOperationCursor(request.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	// Read one extra row so the response can expose an opaque continuation
	// cursor without a separate count query.
	records, err := s.repository.ListOperations(
		ctx, request.GetInterfaceId(), request.GetState(), pageSize+1, before, beforeID,
	)
	if err != nil {
		if strings.Contains(err.Error(), "state filter") {
			return nil, status.Error(codes.InvalidArgument, "invalid state filter")
		}
		return nil, internalError(err)
	}
	response := &wiregatev1.ListOperationsResponse{}
	if len(records) > pageSize {
		last := records[pageSize-1]
		response.NextPageToken = encodeOperationCursor(last.CreatedAt, last.ID)
		records = records[:pageSize]
	}
	response.Operations = make([]*wiregatev1.OperationView, 0, len(records))
	for _, record := range records {
		response.Operations = append(response.Operations, operationMessage(record))
	}
	return response, nil
}

func operationMessage(record agentoperation.Record) *wiregatev1.OperationView {
	var expectedRevision int64
	if record.ExpectedRevision != nil {
		expectedRevision = *record.ExpectedRevision
	}
	message := &wiregatev1.OperationView{
		Id:                   record.ID,
		InterfaceId:          record.InterfaceID,
		OperationType:        record.Type,
		State:                string(record.State),
		ExpectedRevision:     expectedRevision,
		ProposedDiffJson:     record.ProposedDiffJSON,
		ErrorCode:            record.ErrorCode,
		ErrorMessageRedacted: record.ErrorMessageRedacted,
		CreatedAtMs:          timeToMillis(record.CreatedAt),
		UpdatedAtMs:          timeToMillis(record.UpdatedAt),
		FinishedAtMs:         timeToMillis(record.FinishedAt),
		Steps:                make([]*wiregatev1.OperationStepView, 0, len(record.Steps)),
	}
	for _, step := range record.Steps {
		message.Steps = append(message.Steps, &wiregatev1.OperationStepView{
			Id: step.ID, StepOrder: int32(step.Order), Name: step.Name,
			State: string(step.State), EffectKind: step.Kind,
			ErrorRedacted: step.ErrorRedacted,
		})
	}
	return message
}

type operationCursor struct {
	CreatedAtMS int64  `json:"created_at_ms"`
	ID          string `json:"id"`
}

func encodeOperationCursor(createdAt time.Time, id string) string {
	encoded, _ := json.Marshal(operationCursor{CreatedAtMS: createdAt.UnixMilli(), ID: id})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeOperationCursor(value string) (time.Time, string, error) {
	if value == "" {
		return time.Time{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > 512 {
		return time.Time{}, "", errors.New("invalid cursor encoding")
	}
	var cursor operationCursor
	if err := json.Unmarshal(raw, &cursor); err != nil ||
		cursor.CreatedAtMS <= 0 || cursor.ID == "" || len(cursor.ID) > 128 {
		return time.Time{}, "", errors.New("invalid cursor")
	}
	return time.UnixMilli(cursor.CreatedAtMS).UTC(), cursor.ID, nil
}

func validateArtifactActor(actor *wiregatev1.ActorContext) error {
	if actor == nil || actor.GetActorId() == "" || actor.GetRequestId() == "" ||
		(actor.GetActorRole() != "admin" && actor.GetActorRole() != "operator") ||
		actor.GetPermission() != "client:export-secret" {
		return status.Error(codes.PermissionDenied, "artifact permission denied")
	}
	return nil
}

func interfaceMessage(record repository.InterfaceRecord) *wiregatev1.InterfaceView {
	addresses := make([]*wiregatev1.InterfaceAddress, 0, len(record.Addresses))
	for _, address := range record.Addresses {
		addresses = append(addresses, &wiregatev1.InterfaceAddress{
			Family:       int32(address.Family),
			Address:      address.Address,
			PrefixLength: int32(address.PrefixLength),
			Source:       address.Source,
		})
	}
	return &wiregatev1.InterfaceView{
		Id:                 record.ID,
		Name:               record.Name,
		Backend:            backend(record.Backend),
		ManagementMode:     managementMode(record.ManagementMode),
		ConfigPath:         record.ConfigPath,
		ServiceUnit:        record.ServiceUnit,
		FileHash:           record.FileHash,
		RuntimeFingerprint: record.RuntimeFingerprint,
		Revision:           record.Revision,
		DriftState:         driftState(record.DriftState),
		RuntimePresent:     record.RuntimePresent,
		ConfigPresent:      record.ConfigPresent,
		Addresses:          addresses,
		PeerCount:          int32(record.PeerCount),
		UpdatedAtMs:        record.UpdatedAt.UnixMilli(),
		ListenPort:         uint32(record.ListenPort),
		PublicKey:          record.PublicKey,
		DeploymentProfile:  record.DeploymentProfile,
		FirewallMode:       record.FirewallMode,
		AutoStart:          record.AutoStart,
		ServiceState:       record.ServiceState,
	}
}

func peerMessage(record repository.PeerRecord) *wiregatev1.PeerView {
	return &wiregatev1.PeerView{
		Id:                         record.ID,
		InterfaceId:                record.InterfaceID,
		Name:                       record.Name,
		PublicKey:                  record.PublicKey,
		KeyMode:                    record.KeyMode,
		LifecycleState:             record.LifecycleState,
		Endpoint:                   record.Endpoint,
		PersistentKeepaliveSeconds: int32(record.PersistentKeepalive),
		AllowedIps:                 append([]string(nil), record.AllowedIPs...),
		LatestHandshakeAtMs:        timeToMillis(record.LatestHandshakeAt),
		TransferRxBytes:            record.TransferRXBytes,
		TransferTxBytes:            record.TransferTXBytes,
		ActivityState:              record.ActivityState,
		RuntimeSeenAtMs:            timeToMillis(record.RuntimeSeenAt),
	}
}

func backend(value string) wiregatev1.InterfaceBackend {
	switch value {
	case "wg_quick":
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_WG_QUICK
	case "runtime_only":
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_RUNTIME_ONLY
	case "networkmanager":
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_NETWORK_MANAGER
	case "networkd":
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_NETWORKD
	case "container":
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_CONTAINER
	default:
		return wiregatev1.InterfaceBackend_INTERFACE_BACKEND_UNKNOWN
	}
}

func managementMode(value string) wiregatev1.ManagementMode {
	switch value {
	case "observed":
		return wiregatev1.ManagementMode_MANAGEMENT_MODE_OBSERVED
	case "adopted":
		return wiregatev1.ManagementMode_MANAGEMENT_MODE_ADOPTED
	case "managed":
		return wiregatev1.ManagementMode_MANAGEMENT_MODE_MANAGED
	case "unsupported":
		return wiregatev1.ManagementMode_MANAGEMENT_MODE_UNSUPPORTED
	default:
		return wiregatev1.ManagementMode_MANAGEMENT_MODE_UNSPECIFIED
	}
}

func driftState(value string) wiregatev1.DriftState {
	switch value {
	case "none":
		return wiregatev1.DriftState_DRIFT_STATE_NONE
	case "file":
		return wiregatev1.DriftState_DRIFT_STATE_FILE
	case "runtime":
		return wiregatev1.DriftState_DRIFT_STATE_RUNTIME
	case "both":
		return wiregatev1.DriftState_DRIFT_STATE_BOTH
	case "secret":
		return wiregatev1.DriftState_DRIFT_STATE_SECRET
	case "unknown":
		return wiregatev1.DriftState_DRIFT_STATE_UNKNOWN
	default:
		return wiregatev1.DriftState_DRIFT_STATE_UNSPECIFIED
	}
}

func unaryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		request any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		started := time.Now()
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			timeout := 5 * time.Second
			switch {
			case info.FullMethod == wiregatev1.WireGateAgentService_RefreshInventory_FullMethodName,
				strings.Contains(info.FullMethod, "/Preview"),
				strings.Contains(info.FullMethod, "/Prepare"):
				timeout = 10 * time.Second
			case strings.Contains(info.FullMethod, "/Export"),
				strings.Contains(info.FullMethod, "/Consume"):
				timeout = 15 * time.Second
			case strings.Contains(info.FullMethod, "/Commit"),
				strings.Contains(info.FullMethod, "/Create"),
				strings.Contains(info.FullMethod, "/Update"),
				strings.Contains(info.FullMethod, "/Disable"),
				strings.Contains(info.FullMethod, "/Enable"),
				strings.Contains(info.FullMethod, "/Revoke"),
				strings.Contains(info.FullMethod, "/Resolve"),
				strings.Contains(info.FullMethod, "/Rollback"),
				strings.Contains(info.FullMethod, "/Set"):
				timeout = 30 * time.Second
			}
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		response, err := handler(ctx, request)
		logger.Info(
			"agent rpc",
			"method", info.FullMethod,
			"status", status.Code(err).String(),
			"duration_ms", time.Since(started).Milliseconds(),
		)
		return response, err
	}
}

func streamInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(
		server any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		started := time.Now()
		ctx := stream.Context()
		var cancel context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			stream = &contextServerStream{ServerStream: stream, ctx: ctx}
		}
		err := handler(server, stream)
		logger.Info(
			"agent stream rpc",
			"method", info.FullMethod,
			"status", status.Code(err).String(),
			"duration_ms", time.Since(started).Milliseconds(),
		)
		return err
	}
}

type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context {
	return s.ctx
}

func internalError(error) error {
	// Detailed errors can contain host paths or database details. They are
	// intentionally kept out of the RPC response and observed server-side via
	// structured logs and diagnostics.
	return status.Error(codes.Internal, "agent operation failed")
}

func timeToMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func firstError(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func adoptionActor(mutation *wiregatev1.MutationContext) adoption.Actor {
	actor := mutation.GetActor()
	result := adoption.Actor{
		ID: actor.GetActorId(), Role: actor.GetActorRole(),
		RequestID: actor.GetRequestId(), Permission: actor.GetPermission(),
		IdempotencyKey: mutation.GetIdempotencyKey(),
	}
	if mutation.Reason != nil {
		result.Reason = mutation.GetReason()
	}
	return result
}

func controlActor(mutation *wiregatev1.MutationContext) control.Actor {
	actor := mutation.GetActor()
	return control.Actor{
		ID: actor.GetActorId(), Role: actor.GetActorRole(),
		RequestID: actor.GetRequestId(), Permission: actor.GetPermission(),
		IdempotencyKey: mutation.GetIdempotencyKey(), Reason: mutation.GetReason(),
	}
}

func controlError(err error) error {
	message := func(fallback string) string {
		var actionable interface{ PublicMessage() string }
		if errors.As(err, &actionable) {
			value := strings.TrimSpace(actionable.PublicMessage())
			if value != "" && len(value) <= 320 && !strings.ContainsAny(value, "\r\n") {
				return "wiregate-safe-v1: " + value
			}
		}
		return fallback
	}
	switch {
	case errors.Is(err, control.ErrPermission):
		return status.Error(codes.PermissionDenied, message("control permission denied"))
	case errors.Is(err, control.ErrInvalid):
		return status.Error(codes.InvalidArgument, message("control validation failed"))
	case errors.Is(err, control.ErrConflict):
		return status.Error(codes.Aborted, message("control revision conflict"))
	case errors.Is(err, control.ErrPrecondition):
		return status.Error(codes.FailedPrecondition, message("control precondition failed"))
	case errors.Is(err, control.ErrNotFound):
		return status.Error(codes.NotFound, message("control resource not found"))
	default:
		return internalError(err)
	}
}

func adoptionError(err error) error {
	switch {
	case errors.Is(err, adoption.ErrPermission):
		return status.Error(codes.PermissionDenied, "adoption permission denied")
	case errors.Is(err, adoption.ErrRevisionConflict):
		return status.Error(codes.Aborted, "interface revision conflict")
	case errors.Is(err, adoption.ErrNotEligible):
		return status.Error(codes.FailedPrecondition, "interface is not eligible for adoption")
	default:
		return internalError(err)
	}
}

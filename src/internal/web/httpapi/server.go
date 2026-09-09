// File: src/internal/web/httpapi/server.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
	"github.com/wiregate-project/wiregate/internal/web/agentclient"
	"github.com/wiregate-project/wiregate/internal/web/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Agent interface {
	GetAgentInfo(context.Context) (*wiregatev1.GetAgentInfoResponse, error)
	ListInterfaces(context.Context) (*wiregatev1.ListInterfacesResponse, error)
	GetInterface(context.Context, string) (*wiregatev1.GetInterfaceResponse, error)
	ListPeers(context.Context, string) (*wiregatev1.ListPeersResponse, error)
	GetDiagnostics(context.Context) (*wiregatev1.GetDiagnosticsResponse, error)
	PreviewAdoption(context.Context, *wiregatev1.PreviewAdoptionRequest) (*wiregatev1.OperationPlan, error)
	CommitAdoption(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	PreviewCreateInterface(context.Context, *wiregatev1.PreviewCreateInterfaceRequest) (*wiregatev1.OperationPlan, error)
	CreateInterface(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	PreviewSetInterfaceState(context.Context, *wiregatev1.PreviewSetInterfaceStateRequest) (*wiregatev1.OperationPlan, error)
	SetInterfaceState(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	PreviewCreatePeer(context.Context, *wiregatev1.PreviewCreatePeerRequest) (*wiregatev1.OperationPlan, error)
	CreatePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.CreatePeerResponse, error)
	PreviewUpdatePeer(context.Context, *wiregatev1.PreviewUpdatePeerRequest) (*wiregatev1.OperationPlan, error)
	UpdatePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	PreviewPeerMutation(context.Context, *wiregatev1.PreviewPeerMutationRequest) (*wiregatev1.OperationPlan, error)
	DisablePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	EnablePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	RevokePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error)
	ExportClientArtifact(context.Context, *wiregatev1.ExportClientArtifactRequest) (agentclient.Artifact, error)
	ConsumeOneTimeArtifact(context.Context, *wiregatev1.ConsumeOneTimeArtifactRequest) (agentclient.Artifact, error)
	GetOperation(context.Context, string) (*wiregatev1.GetOperationResponse, error)
	ListOperations(context.Context, *wiregatev1.ListOperationsRequest) (*wiregatev1.ListOperationsResponse, error)
}

type Server struct {
	agent  Agent
	auth   *auth.Manager
	logger *slog.Logger
	ui     http.Handler
}

func New(agent Agent, authManager *auth.Manager, logger *slog.Logger) (*Server, error) {
	if authManager == nil {
		return nil, errors.New("auth manager is required")
	}
	public, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		return nil, err
	}
	return &Server{
		agent:  agent,
		auth:   authManager,
		logger: logger,
		ui:     http.FileServer(http.FS(public)),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/auth/status", s.authStatus)
	mux.HandleFunc("POST /api/v1/auth/bootstrap", s.bootstrap)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("POST /api/v1/auth/reauth", s.reauthenticate)
	mux.HandleFunc("POST /api/v1/auth/password", s.changePassword)
	mux.HandleFunc("GET /api/v1/auth/me", s.me)
	mux.HandleFunc("GET /api/v1/agent", s.agentInfo)
	mux.HandleFunc("GET /api/v1/interfaces", s.interfaces)
	mux.HandleFunc("GET /api/v1/interfaces/{interface_id}", s.interfaceByID)
	mux.HandleFunc("GET /api/v1/interfaces/{interface_id}/peers", s.peers)
	mux.HandleFunc("POST /api/v1/interfaces/previews", s.previewCreateInterface)
	mux.HandleFunc("POST /api/v1/interfaces/{interface_id}/state-previews", s.previewSetInterfaceState)
	mux.HandleFunc("POST /api/v1/interfaces/{interface_id}/peer-previews", s.previewCreatePeer)
	mux.HandleFunc("POST /api/v1/peers/{peer_id}/update-previews", s.previewUpdatePeer)
	mux.HandleFunc("POST /api/v1/peers/{peer_id}/exports", s.exportClient)
	mux.HandleFunc("POST /api/v1/peers/{peer_id}/lifecycle-previews", s.previewPeerLifecycle)
	mux.HandleFunc("POST /api/v1/artifacts/consume", s.consumeOneTimeArtifact)
	mux.HandleFunc("POST /api/v1/interfaces/{interface_id}/adoption-previews", s.previewAdoption)
	mux.HandleFunc("POST /api/v1/operations/{operation_id}/commit", s.commitOperation)
	mux.HandleFunc("GET /api/v1/operations", s.operations)
	mux.HandleFunc("GET /api/v1/operations/{operation_id}", s.operationByID)
	mux.HandleFunc("GET /api/v1/diagnostics", s.diagnostics)
	mux.Handle("GET /", s.ui)
	return requestLog(s.logger, securityHeaders(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.agent.GetAgentInfo(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "agent_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) agentInfo(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "interface:view", false); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	response, err := s.agent.GetAgentInfo(ctx)
	s.writeProto(w, response, err)
}

func (s *Server) interfaces(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "interface:view", false); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := s.agent.ListInterfaces(ctx)
	s.writeProto(w, response, err)
}

func (s *Server) interfaceByID(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "interface:view", false); !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("interface_id"))
	if id == "" || len(id) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface id"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := s.agent.GetInterface(ctx, id)
	s.writeProto(w, response, err)
}

func (s *Server) peers(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "client:view", false); !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("interface_id"))
	if id == "" || len(id) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface id"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := s.agent.ListPeers(ctx, id)
	s.writeProto(w, response, err)
}

func (s *Server) diagnostics(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "diagnostic:view", false); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	response, err := s.agent.GetDiagnostics(ctx)
	s.writeProto(w, response, err)
}

func (s *Server) operations(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "operation:view", false); !ok {
		return
	}
	pageSize := int32(0)
	if raw := strings.TrimSpace(request.URL.Query().Get("page_size")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || value < 1 || value > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "page_size must be between 1 and 200"})
			return
		}
		pageSize = int32(value)
	}
	agentRequest := &wiregatev1.ListOperationsRequest{PageSize: pageSize}
	if value := strings.TrimSpace(request.URL.Query().Get("interface_id")); value != "" {
		if len(value) > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface_id"})
			return
		}
		agentRequest.InterfaceId = &value
	}
	if value := strings.TrimSpace(request.URL.Query().Get("state")); value != "" {
		if len(value) > 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid state"})
			return
		}
		agentRequest.State = &value
	}
	if value := strings.TrimSpace(request.URL.Query().Get("page_token")); value != "" {
		if len(value) > 512 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid page_token"})
			return
		}
		agentRequest.PageToken = &value
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := s.agent.ListOperations(ctx, agentRequest)
	s.writeProto(w, response, err)
}

func (s *Server) operationByID(w http.ResponseWriter, request *http.Request) {
	if _, ok := s.require(w, request, "operation:view", false); !ok {
		return
	}
	operationID := strings.TrimSpace(request.PathValue("operation_id"))
	if operationID == "" || len(operationID) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid operation id"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	response, err := s.agent.GetOperation(ctx, operationID)
	s.writeProto(w, response, err)
}

type mutationBody struct {
	Reason string `json:"reason"`
}

type createInterfaceBody struct {
	Name               string   `json:"name"`
	InterfaceAddresses []string `json:"interface_addresses"`
	ListenPort         uint32   `json:"listen_port"`
	DeploymentProfile  string   `json:"deployment_profile"`
	FirewallMode       string   `json:"firewall_mode"`
	LANCIDRs           []string `json:"lan_cidrs"`
	EgressDevice       string   `json:"egress_device"`
	AutoStart          bool     `json:"auto_start"`
	Reason             string   `json:"reason"`
}

type createPeerBody struct {
	Name                string   `json:"name"`
	KeyMode             string   `json:"key_mode"`
	ExternalPublicKey   string   `json:"external_public_key"`
	ServerAllowedIPs    []string `json:"server_allowed_ips"`
	ClientRoutes        []string `json:"client_routes"`
	DNS                 []string `json:"dns"`
	MTU                 uint32   `json:"mtu"`
	EndpointHost        string   `json:"endpoint_host"`
	EndpointPort        uint32   `json:"endpoint_port"`
	PersistentKeepalive uint32   `json:"persistent_keepalive_seconds"`
	UsePresharedKey     bool     `json:"use_preshared_key"`
	Reason              string   `json:"reason"`
}

func (s *Server) previewCreateInterface(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:create", true)
	if !ok {
		return
	}
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key required"})
		return
	}
	var body createInterfaceBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewCreateInterface(ctx, &wiregatev1.PreviewCreateInterfaceRequest{
		Context: mutationContext(
			principal, requestID(request), "interface:create", idempotency, nil, body.Reason,
		),
		Name: body.Name, InterfaceAddresses: body.InterfaceAddresses,
		ListenPort: body.ListenPort, DeploymentProfile: body.DeploymentProfile,
		FirewallMode: body.FirewallMode, LanCidrs: body.LANCIDRs,
		EgressDevice: body.EgressDevice, AutoStart: body.AutoStart,
	})
	s.writeProto(w, response, err)
}

func (s *Server) previewCreatePeer(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "client:manage", true)
	if !ok {
		return
	}
	interfaceID := strings.TrimSpace(request.PathValue("interface_id"))
	if interfaceID == "" || len(interfaceID) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface id"})
		return
	}
	revision, err := parseRevision(request.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid If-Match revision required"})
		return
	}
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key required"})
		return
	}
	var body createPeerBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewCreatePeer(ctx, &wiregatev1.PreviewCreatePeerRequest{
		Context:     mutationContext(principal, requestID(request), "client:manage", idempotency, &revision, body.Reason),
		InterfaceId: interfaceID, Name: body.Name, KeyMode: body.KeyMode,
		ExternalPublicKey: optionalString(body.ExternalPublicKey),
		ServerAllowedIps:  body.ServerAllowedIPs, ClientRoutes: body.ClientRoutes,
		Dns: body.DNS, Mtu: optionalUint32(body.MTU),
		EndpointHost: optionalString(body.EndpointHost), EndpointPort: optionalUint32(body.EndpointPort),
		PersistentKeepaliveSeconds: optionalUint32(body.PersistentKeepalive),
		UsePresharedKey:            body.UsePresharedKey,
	})
	s.writeProto(w, response, err)
}

type interfaceStateBody struct {
	DesiredState string `json:"desired_state"`
	Reason       string `json:"reason"`
}

func (s *Server) previewSetInterfaceState(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:manage", true)
	if !ok {
		return
	}
	interfaceID := strings.TrimSpace(request.PathValue("interface_id"))
	revision, revisionErr := parseRevision(request.Header.Get("If-Match"))
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if interfaceID == "" || len(interfaceID) > 128 || revisionErr != nil ||
		idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "interface, If-Match and Idempotency-Key required",
		})
		return
	}
	var body interfaceStateBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	if strings.ToLower(strings.TrimSpace(body.DesiredState)) != "removed" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "desired_state must be removed"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewSetInterfaceState(ctx, &wiregatev1.PreviewSetInterfaceStateRequest{
		Context: mutationContext(
			principal, requestID(request), "interface:manage", idempotency, &revision, body.Reason,
		),
		InterfaceId: interfaceID, DesiredState: "removed",
	})
	s.writeProto(w, response, err)
}

type peerLifecycleBody struct {
	Mutation string `json:"mutation"`
	Reason   string `json:"reason"`
}

type updatePeerBody struct {
	Name                *string  `json:"name"`
	ServerAllowedIPs    []string `json:"server_allowed_ips"`
	ClientRoutes        []string `json:"client_routes"`
	Endpoint            *string  `json:"endpoint"`
	PersistentKeepalive *uint32  `json:"persistent_keepalive_seconds"`
	Reason              string   `json:"reason"`
}

func (s *Server) previewUpdatePeer(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "client:manage", true)
	if !ok {
		return
	}
	peerID := strings.TrimSpace(request.PathValue("peer_id"))
	revision, revisionErr := parseRevision(request.Header.Get("If-Match"))
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if peerID == "" || len(peerID) > 128 || revisionErr != nil ||
		idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "peer, If-Match and Idempotency-Key required",
		})
		return
	}
	var body updatePeerBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewUpdatePeer(ctx, &wiregatev1.PreviewUpdatePeerRequest{
		Context: mutationContext(
			principal, requestID(request), "client:manage", idempotency, &revision, body.Reason,
		),
		PeerId: peerID, Name: body.Name, ServerAllowedIps: body.ServerAllowedIPs,
		ClientRoutes: body.ClientRoutes, Endpoint: body.Endpoint,
		PersistentKeepaliveSeconds: body.PersistentKeepalive,
	})
	s.writeProto(w, response, err)
}

func (s *Server) previewPeerLifecycle(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "client:manage", true)
	if !ok {
		return
	}
	peerID := strings.TrimSpace(request.PathValue("peer_id"))
	revision, revisionErr := parseRevision(request.Header.Get("If-Match"))
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if peerID == "" || len(peerID) > 128 || revisionErr != nil || idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer, If-Match and Idempotency-Key required"})
		return
	}
	var body peerLifecycleBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(body.Mutation), "revoke") {
		if err := s.auth.RequireRecentReauth(principal); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent password confirmation required"})
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewPeerMutation(ctx, &wiregatev1.PreviewPeerMutationRequest{
		Context: mutationContext(principal, requestID(request), "client:manage", idempotency, &revision, body.Reason),
		PeerId:  peerID, Mutation: strings.ToLower(strings.TrimSpace(body.Mutation)),
	})
	s.writeProto(w, response, err)
}

type artifactBody struct {
	Format string `json:"format"`
	Token  string `json:"token"`
}

func (s *Server) exportClient(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "client:export-secret", true)
	if !ok {
		return
	}
	if err := s.auth.RequireRecentReauth(principal); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent password confirmation required"})
		return
	}
	peerID := strings.TrimSpace(request.PathValue("peer_id"))
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if peerID == "" || len(peerID) > 128 || idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer and Idempotency-Key required"})
		return
	}
	var body artifactBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	format, ok := artifactFormat(body.Format)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be conf or qr"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	artifact, err := s.agent.ExportClientArtifact(ctx, &wiregatev1.ExportClientArtifactRequest{
		Actor: artifactActor(principal, requestID(request)), PeerId: peerID,
		Format: format, IdempotencyKey: idempotency,
	})
	s.writeArtifact(w, artifact, err)
}

func (s *Server) consumeOneTimeArtifact(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "client:export-secret", true)
	if !ok {
		return
	}
	if err := s.auth.RequireRecentReauth(principal); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent password confirmation required"})
		return
	}
	var body artifactBody
	if err := decodeJSON(w, request, &body); err != nil {
		return
	}
	format, ok := artifactFormat(body.Format)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be conf or qr"})
		return
	}
	token, err := base64.StdEncoding.DecodeString(body.Token)
	if err != nil {
		token, err = base64.RawURLEncoding.DecodeString(body.Token)
	}
	if err != nil || len(token) != 32 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "artifact unavailable"})
		return
	}
	defer clear(token)
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	artifact, err := s.agent.ConsumeOneTimeArtifact(ctx, &wiregatev1.ConsumeOneTimeArtifactRequest{
		Actor: artifactActor(principal, requestID(request)), Token: token, Format: format,
	})
	s.writeArtifact(w, artifact, err)
}

func artifactFormat(value string) (wiregatev1.ArtifactFormat, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "conf":
		return wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_WIREGUARD_CONF, true
	case "qr":
		return wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_QR_PNG, true
	default:
		return wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_UNSPECIFIED, false
	}
}

func artifactActor(principal auth.Principal, requestID string) *wiregatev1.ActorContext {
	evidence := "session-reauth"
	return &wiregatev1.ActorContext{
		ActorId: principal.UserID, ActorRole: principal.Role, RequestId: requestID,
		Permission: "client:export-secret", ReauthEvidenceId: &evidence,
	}
}

func (s *Server) writeArtifact(w http.ResponseWriter, artifact agentclient.Artifact, err error) {
	if err != nil {
		s.writeProto(w, nil, err)
		return
	}
	defer clear(artifact.Data)
	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(artifact.Filename, `"`, "")+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact.Data)
}

func (s *Server) previewAdoption(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:adopt", true)
	if !ok {
		return
	}
	interfaceID := strings.TrimSpace(request.PathValue("interface_id"))
	if interfaceID == "" || len(interfaceID) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface id"})
		return
	}
	revision, err := parseRevision(request.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid If-Match revision required"})
		return
	}
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key required"})
		return
	}
	var body mutationBody
	if request.ContentLength != 0 {
		if err := decodeJSON(w, request, &body); err != nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := s.agent.PreviewAdoption(ctx, &wiregatev1.PreviewAdoptionRequest{
		InterfaceId: interfaceID,
		Context: mutationContext(
			principal, requestID(request), "interface:adopt",
			idempotency, &revision, body.Reason,
		),
	})
	s.writeProto(w, response, err)
}

func (s *Server) commitOperation(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "operation:view", false)
	if !ok {
		return
	}
	operationID := strings.TrimSpace(request.PathValue("operation_id"))
	if operationID == "" || len(operationID) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid operation id"})
		return
	}
	lookupContext, lookupCancel := context.WithTimeout(request.Context(), 5*time.Second)
	operation, lookupErr := s.agent.GetOperation(lookupContext, operationID)
	lookupCancel()
	if lookupErr != nil || operation.GetOperation() == nil {
		s.writeProto(w, operation, lookupErr)
		return
	}
	permission := ""
	switch operation.GetOperation().GetOperationType() {
	case "adopt_interface":
		permission = "interface:adopt"
	case "create_interface":
		permission = "interface:create"
	case "set_interface_state":
		permission = "interface:manage"
	case "create_peer", "update_peer":
		permission = "client:manage"
	case "disable_peer", "enable_peer", "revoke_peer":
		permission = "client:manage"
	default:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "operation type is not committable"})
		return
	}
	principal, ok = s.require(w, request, permission, true)
	if !ok {
		return
	}
	if operation.GetOperation().GetOperationType() == "revoke_peer" ||
		operation.GetOperation().GetOperationType() == "set_interface_state" {
		if err := s.auth.RequireRecentReauth(principal); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent password confirmation required"})
			return
		}
	}
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotency == "" || len(idempotency) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key required"})
		return
	}
	var body mutationBody
	if request.ContentLength != 0 {
		if err := decodeJSON(w, request, &body); err != nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	agentRequest := &wiregatev1.CommitOperationRequest{
		OperationId: operationID,
		Context: mutationContext(
			principal, requestID(request), permission,
			idempotency, nil, body.Reason,
		),
	}
	var response proto.Message
	var err error
	switch operation.GetOperation().GetOperationType() {
	case "create_interface":
		response, err = s.agent.CreateInterface(ctx, agentRequest)
	case "set_interface_state":
		response, err = s.agent.SetInterfaceState(ctx, agentRequest)
	case "create_peer":
		response, err = s.agent.CreatePeer(ctx, agentRequest)
	case "update_peer":
		response, err = s.agent.UpdatePeer(ctx, agentRequest)
	case "disable_peer":
		response, err = s.agent.DisablePeer(ctx, agentRequest)
	case "enable_peer":
		response, err = s.agent.EnablePeer(ctx, agentRequest)
	case "revoke_peer":
		response, err = s.agent.RevokePeer(ctx, agentRequest)
	default:
		response, err = s.agent.CommitAdoption(ctx, agentRequest)
	}
	s.writeProto(w, response, err)
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func optionalUint32(value uint32) *uint32 {
	if value == 0 {
		return nil
	}
	return &value
}

func (s *Server) authStatus(w http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	bootstrapRequired, err := s.auth.BootstrapRequired(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication status unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"bootstrap_required": bootstrapRequired})
}

func mutationContext(
	principal auth.Principal,
	requestID, permission, idempotency string,
	expectedRevision *int64,
	reason string,
) *wiregatev1.MutationContext {
	result := &wiregatev1.MutationContext{
		Actor: &wiregatev1.ActorContext{
			ActorId: principal.UserID, ActorRole: principal.Role,
			RequestId: requestID, Permission: permission,
		},
		IdempotencyKey: idempotency, ExpectedRevision: expectedRevision,
	}
	if reason != "" {
		result.Reason = &reason
	}
	return result
}

func parseRevision(value string) (int64, error) {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return 0, errors.New("revision is empty")
	}
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 0 {
		return 0, errors.New("invalid revision")
	}
	return revision, nil
}

type bootstrapRequest struct {
	Token       string `json:"token"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

func (s *Server) bootstrap(w http.ResponseWriter, request *http.Request) {
	if !auth.ValidOrigin(request) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "request origin rejected"})
		return
	}
	var input bootstrapRequest
	if err := decodeJSON(w, request, &input); err != nil {
		return
	}
	user, err := s.auth.Bootstrap(
		request.Context(), input.Token, input.Username, input.DisplayName,
		input.Password, requestID(request),
	)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "bootstrap unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, publicUser(user.ID, user.Username, user.DisplayName, user.Role))
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, request *http.Request) {
	if !auth.ValidOrigin(request) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "request origin rejected"})
		return
	}
	var input loginRequest
	if err := decodeJSON(w, request, &input); err != nil {
		return
	}
	user, tokens, err := s.auth.Login(
		request.Context(), input.Username, input.Password,
		requestID(request), remoteIP(request),
	)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	auth.SetSessionCookie(w, tokens.Session, time.Now().UTC().Add(12*time.Hour))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       publicUser(user.ID, user.Username, user.DisplayName, user.Role),
		"csrf_token": tokens.CSRF,
	})
}

type passwordConfirmation struct {
	Password string `json:"password"`
}

func (s *Server) reauthenticate(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:view", true)
	if !ok {
		return
	}
	var input passwordConfirmation
	if err := decodeJSON(w, request, &input); err != nil {
		return
	}
	until, err := s.auth.Reauthenticate(request.Context(), principal, input.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password confirmation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"reauth_until_ms": until.UnixMilli()})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:view", true)
	if !ok {
		return
	}
	var input changePasswordRequest
	if err := decodeJSON(w, request, &input); err != nil {
		return
	}
	if err := s.auth.ChangePassword(
		request.Context(), principal, input.CurrentPassword, input.NewPassword,
	); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password change rejected"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:view", true)
	if !ok {
		return
	}
	if err := s.auth.Logout(request.Context(), principal); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout failed"})
		return
	}
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, request *http.Request) {
	principal, ok := s.require(w, request, "interface:view", false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, publicUser(
		principal.UserID, principal.Username, principal.DisplayName, principal.Role,
	))
}

func (s *Server) require(
	w http.ResponseWriter,
	request *http.Request,
	permission string,
	mutation bool,
) (auth.Principal, bool) {
	principal, err := s.auth.Require(request.Context(), request, permission, mutation)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return auth.Principal{}, false
	case err != nil:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "permission denied"})
		return auth.Principal{}, false
	default:
		return principal, true
	}
}

func decodeJSON(w http.ResponseWriter, request *http.Request, target any) error {
	if contentType := request.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json required"})
		return errors.New("invalid content type")
	}
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only one JSON value is allowed"})
		return errors.New("trailing JSON value")
	}
	return nil
}

func requestID(request *http.Request) string {
	value := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if value != "" && len(value) <= 128 {
		return value
	}
	generated, err := ids.NewV7(time.Now().UTC())
	if err != nil {
		return "request-id-unavailable"
	}
	return generated
}

func remoteIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func publicUser(id, username, displayName, role string) map[string]string {
	return map[string]string{
		"id": id, "username": username, "display_name": displayName, "role": role,
	}
}

func (s *Server) writeProto(w http.ResponseWriter, message proto.Message, err error) {
	if err != nil {
		code := status.Code(err)
		agentMessage := status.Convert(err).Message()
		httpStatus := http.StatusBadGateway
		publicError := "agent request failed"
		switch code {
		case codes.InvalidArgument:
			httpStatus = http.StatusBadRequest
			publicError = "invalid request"
		case codes.NotFound:
			httpStatus = http.StatusNotFound
			publicError = "resource not found"
		case codes.DeadlineExceeded, codes.Unavailable:
			httpStatus = http.StatusServiceUnavailable
			publicError = "agent unavailable"
		case codes.Aborted:
			httpStatus = http.StatusConflict
			publicError = "revision conflict"
		case codes.FailedPrecondition:
			httpStatus = http.StatusConflict
			publicError = "operation precondition failed"
		case codes.PermissionDenied:
			httpStatus = http.StatusForbidden
			publicError = "permission denied"
		}
		const safePrefix = "wiregate-safe-v1: "
		if strings.HasPrefix(agentMessage, safePrefix) {
			candidate := strings.TrimSpace(strings.TrimPrefix(agentMessage, safePrefix))
			if candidate != "" && len(candidate) <= 320 && !strings.ContainsAny(candidate, "\r\n") {
				publicError = candidate
			}
		}
		writeJSON(w, httpStatus, map[string]string{"error": publicError})
		return
	}
	body, err := (protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}).Marshal(message)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "response encoding failed"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, request)
	})
}

func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		logger.Info(
			"web request",
			"method", request.Method,
			"path", request.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

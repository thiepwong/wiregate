// File: src/internal/web/httpapi/server_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"github.com/wiregate-project/wiregate/internal/web/agentclient"
	"github.com/wiregate-project/wiregate/internal/web/auth"
	"github.com/wiregate-project/wiregate/internal/web/repository"
)

type fakeAgent struct{}

func (fakeAgent) GetAgentInfo(context.Context) (*wiregatev1.GetAgentInfoResponse, error) {
	return &wiregatev1.GetAgentInfoResponse{Agent: &wiregatev1.AgentInfo{}}, nil
}
func (fakeAgent) ListInterfaces(context.Context) (*wiregatev1.ListInterfacesResponse, error) {
	return &wiregatev1.ListInterfacesResponse{}, nil
}
func (fakeAgent) GetInterface(context.Context, string) (*wiregatev1.GetInterfaceResponse, error) {
	return &wiregatev1.GetInterfaceResponse{}, nil
}
func (fakeAgent) ListPeers(context.Context, string) (*wiregatev1.ListPeersResponse, error) {
	return &wiregatev1.ListPeersResponse{}, nil
}
func (fakeAgent) GetDiagnostics(context.Context) (*wiregatev1.GetDiagnosticsResponse, error) {
	return &wiregatev1.GetDiagnosticsResponse{}, nil
}
func (fakeAgent) PreviewAdoption(context.Context, *wiregatev1.PreviewAdoptionRequest) (*wiregatev1.OperationPlan, error) {
	return &wiregatev1.OperationPlan{}, nil
}
func (fakeAgent) CommitAdoption(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) PreviewCreateInterface(context.Context, *wiregatev1.PreviewCreateInterfaceRequest) (*wiregatev1.OperationPlan, error) {
	return &wiregatev1.OperationPlan{}, nil
}
func (fakeAgent) CreateInterface(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) PreviewCreatePeer(context.Context, *wiregatev1.PreviewCreatePeerRequest) (*wiregatev1.OperationPlan, error) {
	return &wiregatev1.OperationPlan{}, nil
}
func (fakeAgent) CreatePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.CreatePeerResponse, error) {
	return &wiregatev1.CreatePeerResponse{}, nil
}
func (fakeAgent) PreviewUpdatePeer(context.Context, *wiregatev1.PreviewUpdatePeerRequest) (*wiregatev1.OperationPlan, error) {
	return &wiregatev1.OperationPlan{}, nil
}
func (fakeAgent) UpdatePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) PreviewPeerMutation(context.Context, *wiregatev1.PreviewPeerMutationRequest) (*wiregatev1.OperationPlan, error) {
	return &wiregatev1.OperationPlan{}, nil
}
func (fakeAgent) DisablePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) EnablePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) RevokePeer(context.Context, *wiregatev1.CommitOperationRequest) (*wiregatev1.OperationRef, error) {
	return &wiregatev1.OperationRef{}, nil
}
func (fakeAgent) ExportClientArtifact(context.Context, *wiregatev1.ExportClientArtifactRequest) (agentclient.Artifact, error) {
	return agentclient.Artifact{}, nil
}
func (fakeAgent) ConsumeOneTimeArtifact(context.Context, *wiregatev1.ConsumeOneTimeArtifactRequest) (agentclient.Artifact, error) {
	return agentclient.Artifact{}, nil
}
func (fakeAgent) GetOperation(context.Context, string) (*wiregatev1.GetOperationResponse, error) {
	return &wiregatev1.GetOperationResponse{}, nil
}
func (fakeAgent) ListOperations(context.Context, *wiregatev1.ListOperationsRequest) (*wiregatev1.ListOperationsResponse, error) {
	return &wiregatev1.ListOperationsResponse{}, nil
}

func TestWireGuardAPIRequiresSession(t *testing.T) {
	store, err := repository.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := auth.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(fakeAgent{}, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://gateway.test/api/v1/interfaces", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestAuthStatusHidesBootstrapAfterFirstAdmin(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := auth.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(fakeAgent{}, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	statusRequest := httptest.NewRequest(http.MethodGet, "https://gateway.test/api/v1/auth/status", nil)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"bootstrap_required":true`) {
		t.Fatalf("initial status = %d, body = %s", statusResponse.Code, statusResponse.Body.String())
	}

	pageRequest := httptest.NewRequest(http.MethodGet, "https://gateway.test/", nil)
	pageResponse := httptest.NewRecorder()
	handler.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK || !strings.Contains(pageResponse.Body.String(), `<details id="bootstrap-setup" hidden>`) {
		t.Fatalf("login page must hide bootstrap by default: status = %d", pageResponse.Code)
	}

	now := time.Now().UTC()
	token, tokenHash, err := auth.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetBootstrapToken(ctx, tokenHash, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bootstrap(
		ctx, token, "admin", "Admin", "correct horse battery staple", "request-1",
	); err != nil {
		t.Fatal(err)
	}

	statusResponse = httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"bootstrap_required":false`) {
		t.Fatalf("post-bootstrap status = %d, body = %s", statusResponse.Code, statusResponse.Body.String())
	}
}

func TestAuthenticatedViewerCanReadButCannotMutate(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	token, tokenHash, err := auth.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetBootstrapToken(ctx, tokenHash, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	manager, _ := auth.NewManager(store)
	if _, err := manager.Bootstrap(
		ctx, token, "admin", "Admin", "correct horse battery staple", "request-1",
	); err != nil {
		t.Fatal(err)
	}
	_, tokens, err := manager.Login(
		ctx, "admin", "correct horse battery staple", "request-2", "127.0.0.1",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := New(fakeAgent{}, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "https://gateway.test/api/v1/interfaces", nil)
	request.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tokens.Session})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	principal, err := manager.Authenticate(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Role != "admin" || !auth.Allowed(principal.Role, "interface:adopt") {
		t.Fatalf("principal = %#v", principal)
	}
}

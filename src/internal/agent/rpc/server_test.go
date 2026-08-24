// File: src/internal/agent/rpc/server_test.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package rpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"github.com/wiregate-project/wiregate/internal/agent/artifact"
	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const rpcTestGatewayID = "01900000-0000-7000-8000-000000000001"

func TestConsumeOneTimeArtifactStreamsOnce(t *testing.T) {
	ctx := context.Background()
	store, err := repository.Open(ctx, filepath.Join(t.TempDir(), "agent.db"), rpcTestGatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.ReplaceInventory(ctx, inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ConfigPresent: true,
			Peers: []inventory.Peer{{
				Name:      "peer",
				PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
				AllowedIPs: []string{
					"10.0.0.2/32",
				},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, _ := store.ListInterfaces(ctx)
	peers, _ := store.ListPeers(ctx, interfaces[0].ID)
	master := bytes.Repeat([]byte{7}, 32)
	artifacts, err := artifact.NewService(store, func(uint32) ([]byte, error) {
		return bytes.Clone(master), nil
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("[Interface]\nPrivateKey = redacted-in-test\n")
	_, token, err := artifacts.Create(ctx, peers[0].ID, secret.Context{
		GatewayID: rpcTestGatewayID, OwnerType: "artifact",
		OwnerID: peers[0].ID, Purpose: "one_time_payload",
	}, payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, nil, rpcTestGatewayID)
	server.EnableArtifacts(artifacts)
	request := &wiregatev1.ConsumeOneTimeArtifactRequest{
		Actor: &wiregatev1.ActorContext{
			ActorId: "admin", ActorRole: "admin", RequestId: "request",
			Permission: "client:export-secret",
		},
		Token: token, Format: wiregatev1.ArtifactFormat_ARTIFACT_FORMAT_WIREGUARD_CONF,
	}
	stream := &testArtifactStream{ctx: ctx}
	if err := server.ConsumeOneTimeArtifact(request, stream); err != nil {
		t.Fatal(err)
	}
	var received []byte
	for _, chunk := range stream.chunks {
		received = append(received, chunk.GetData()...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("streamed payload = %q", received)
	}
	if len(stream.chunks) == 0 ||
		stream.chunks[0].GetContentType() != "text/plain; charset=utf-8" ||
		!strings.HasSuffix(stream.chunks[0].GetFilename(), ".conf") {
		t.Fatalf("artifact metadata = %#v", stream.chunks)
	}
	replay := &testArtifactStream{ctx: ctx}
	if err := server.ConsumeOneTimeArtifact(request, replay); status.Code(err) != codes.NotFound {
		t.Fatalf("replay status = %v, want NotFound", status.Code(err))
	}

	_, interruptedToken, err := artifacts.Create(ctx, peers[0].ID, secret.Context{
		GatewayID: rpcTestGatewayID, OwnerType: "artifact",
		OwnerID: peers[0].ID + "-interrupted", Purpose: "one_time_payload",
	}, payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	interruptedRequest := &wiregatev1.ConsumeOneTimeArtifactRequest{
		Actor: request.Actor, Token: interruptedToken, Format: request.Format,
	}
	interrupted := &testArtifactStream{ctx: ctx, sendErr: errors.New("client disconnected")}
	if err := server.ConsumeOneTimeArtifact(interruptedRequest, interrupted); err == nil {
		t.Fatal("interrupted stream unexpectedly succeeded")
	}
	if err := server.ConsumeOneTimeArtifact(
		interruptedRequest, &testArtifactStream{ctx: ctx},
	); status.Code(err) != codes.NotFound {
		t.Fatalf("interrupted artifact replay status = %v, want NotFound", status.Code(err))
	}
}

func TestOperationCursorRejectsTampering(t *testing.T) {
	if _, _, err := decodeOperationCursor("not-a-valid-token"); err == nil {
		t.Fatal("tampered operation cursor was accepted")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	token := encodeOperationCursor(now, "operation-id")
	decoded, id, err := decodeOperationCursor(token)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(now) || id != "operation-id" {
		t.Fatalf("decoded cursor = %s %q", decoded, id)
	}
}

type testArtifactStream struct {
	ctx     context.Context
	chunks  []*wiregatev1.ArtifactChunk
	sendErr error
}

func (s *testArtifactStream) Send(chunk *wiregatev1.ArtifactChunk) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.chunks = append(s.chunks, chunk)
	return nil
}

func (*testArtifactStream) SetHeader(metadata.MD) error  { return nil }
func (*testArtifactStream) SendHeader(metadata.MD) error { return nil }
func (*testArtifactStream) SetTrailer(metadata.MD)       {}
func (s *testArtifactStream) Context() context.Context   { return s.ctx }
func (*testArtifactStream) SendMsg(any) error            { return nil }
func (*testArtifactStream) RecvMsg(any) error            { return nil }

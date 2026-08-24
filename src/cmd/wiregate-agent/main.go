// File: src/cmd/wiregate-agent/main.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	wiregatev1 "github.com/wiregate-project/wiregate/gen/wiregate/v1"
	"github.com/wiregate-project/wiregate/internal/agent/adapters/configfile"
	filesystemadapter "github.com/wiregate-project/wiregate/internal/agent/adapters/filesystem"
	netlinksource "github.com/wiregate-project/wiregate/internal/agent/adapters/netlink"
	wgctrlsource "github.com/wiregate-project/wiregate/internal/agent/adapters/wgctrl"
	"github.com/wiregate-project/wiregate/internal/agent/adoption"
	"github.com/wiregate-project/wiregate/internal/agent/artifact"
	agentconfig "github.com/wiregate-project/wiregate/internal/agent/config"
	"github.com/wiregate-project/wiregate/internal/agent/control"
	"github.com/wiregate-project/wiregate/internal/agent/inventory"
	"github.com/wiregate-project/wiregate/internal/agent/repository"
	agentrpc "github.com/wiregate-project/wiregate/internal/agent/rpc"
	"github.com/wiregate-project/wiregate/internal/agent/secret"
	"github.com/wiregate-project/wiregate/internal/agent/transport"
	"github.com/wiregate-project/wiregate/internal/shared/ids"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		initFlags := flag.NewFlagSet("init", flag.ContinueOnError)
		keyDir := initFlags.String("key-dir", "/etc/wiregate/keys", "root-only key directory")
		if err := initFlags.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		keyStore, err := secret.NewKeyStore(*keyDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "initialize key store:", err)
			os.Exit(1)
		}
		gatewayID, err := ids.NewV7(time.Now().UTC())
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate gateway ID:", err)
			os.Exit(1)
		}
		master, fingerprint, err := keyStore.Initialize()
		if err != nil {
			fmt.Fprintln(os.Stderr, "initialize key store:", err)
			os.Exit(1)
		}
		clear(master)
		clear(fingerprint)
		fmt.Fprintln(os.Stdout, gatewayID)
		return
	}
	configPath := flag.String("config", "/etc/wiregate/agent.yaml", "path to agent YAML config")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		logger.Error("load agent config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	repository, err := repository.Open(ctx, cfg.DatabasePath, cfg.GatewayID)
	if err != nil {
		logger.Error("open agent repository", "error", err)
		os.Exit(1)
	}
	defer repository.Close()

	keyStore, keyStoreErr := secret.NewKeyStore(cfg.KeyDir)
	var fingerprintKey []byte
	if keyStoreErr == nil {
		fingerprintKey, keyStoreErr = keyStore.LoadFingerprint()
	}
	fileSource := configfile.New(cfg.WireGuardConfigDir, cfg.AllowsInterface)
	if len(fingerprintKey) == 32 {
		fileSource = configfile.NewWithFingerprint(
			cfg.WireGuardConfigDir, cfg.AllowsInterface, fingerprintKey,
		)
		clear(fingerprintKey)
	}
	inventoryService := inventory.NewService(
		fileSource,
		wgctrlsource.New(),
		netlinksource.New(),
		repository,
		cfg.AllowsInterface,
	)
	refreshContext, refreshCancel := context.WithTimeout(ctx, 10*time.Second)
	if result, err := inventoryService.Refresh(refreshContext); err != nil {
		logger.Warn("initial inventory refresh failed", "error", err)
	} else {
		logger.Info("initial inventory refreshed", "interfaces", result.InterfaceCount, "peers", result.PeerCount)
	}
	refreshCancel()

	listener, err := transport.ListenUnix(
		cfg.SocketPath,
		0o660,
		cfg.AllowedPeerGID,
		cfg.AllowedPeerUID,
		cfg.AllowedPeerGID,
		logger,
	)
	if err != nil {
		logger.Error("open agent Unix socket", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	var adoptionService *adoption.Service
	var adoptionServiceErr error
	var artifactService *artifact.Service
	var artifactServiceErr error
	var controlService *control.Service
	var controlServiceErr error
	files, fileStoreErr := filesystemadapter.New(cfg.WireGuardConfigDir)
	keyVersion, keyVersionErr := repository.CurrentKeyVersion(ctx)
	if keyStoreErr == nil && keyVersionErr == nil {
		if keyVersion == 0 {
			if key, loadErr := keyStore.LoadMaster(1); loadErr == nil {
				clear(key)
				if initErr := repository.InitializeKeyVersion(ctx, 1); initErr == nil {
					keyVersion = 1
				} else {
					keyVersionErr = initErr
				}
			} else {
				keyStoreErr = loadErr
			}
		}
		if keyVersion > 0 && keyVersionErr == nil {
			if key, loadErr := keyStore.LoadMaster(keyVersion); loadErr == nil {
				clear(key)
				artifactService, artifactServiceErr = artifact.NewService(
					repository, keyStore.LoadMaster, keyVersion,
				)
				if artifactServiceErr == nil {
					if recoverErr := artifactService.Recover(ctx); recoverErr != nil {
						logger.Error("recover one-time artifacts", "error", recoverErr)
						os.Exit(1)
					}
				}
				if fileStoreErr == nil {
					adoptionService, adoptionServiceErr = adoption.New(
						repository, files, keyStore.LoadMaster, keyStore.LoadFingerprint,
						cfg.GatewayID, keyVersion,
					)
					controlService, controlServiceErr = control.New(
						repository, files, keyStore.LoadMaster, keyStore.LoadFingerprint,
						cfg.GatewayID, keyVersion, cfg.ArtifactTTL,
						cfg.WireGuardConfigDir, cfg.AllowsInterface,
					)
				}
			} else {
				keyStoreErr = loadErr
			}
		}
	}
	if adoptionService != nil {
		if recoverErr := adoptionService.Recover(ctx); recoverErr != nil {
			logger.Error("recover adoption operations", "error", recoverErr)
			os.Exit(1)
		}
	}
	if controlService != nil {
		if recoverErr := controlService.Recover(ctx); recoverErr != nil {
			logger.Error("recover control operations", "error", recoverErr)
			os.Exit(1)
		}
	}
	if adoptionService == nil {
		logger.Warn(
			"mutating services disabled; agent remains read-only",
			"key_store_error", keyStoreErr,
			"file_store_error", fileStoreErr,
			"key_version_error", keyVersionErr,
			"adoption_service_error", adoptionServiceErr,
			"control_service_error", controlServiceErr,
		)
	}
	if artifactServiceErr != nil {
		logger.Warn("one-time artifact service disabled", "error", artifactServiceErr)
	}

	grpcServer := agentrpc.NewGRPCServer(logger)
	rpcServer := agentrpc.NewServer(repository, inventoryService, cfg.GatewayID, adoptionService)
	rpcServer.EnableArtifacts(artifactService)
	rpcServer.EnableControl(controlService)
	wiregatev1.RegisterWireGateAgentServiceServer(
		grpcServer,
		rpcServer,
	)

	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("wiregate agent listening", "socket", cfg.SocketPath)
		serveErrors <- grpcServer.Serve(listener)
	}()
	go refreshLoop(ctx, logger, inventoryService, minDuration(cfg.RuntimePollInterval, cfg.FileScanInterval))
	if err := transport.NotifySystemd("READY=1\nSTATUS=WireGate agent ready"); err != nil {
		logger.Error("notify systemd readiness", "error", err)
		os.Exit(1)
	}

	select {
	case <-ctx.Done():
		logger.Info("wiregate agent shutting down")
	case err := <-serveErrors:
		if !errors.Is(err, context.Canceled) {
			logger.Error("agent gRPC server stopped", "error", err)
		}
	}
	_ = transport.NotifySystemd("STOPPING=1\nSTATUS=WireGate agent stopping")
	grpcServer.GracefulStop()
}

func refreshLoop(ctx context.Context, logger *slog.Logger, service *inventory.Service, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshContext, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := service.Refresh(refreshContext)
			cancel()
			if err != nil {
				logger.Warn("periodic inventory refresh failed", "error", err)
			}
		}
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

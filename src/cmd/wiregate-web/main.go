// File: src/cmd/wiregate-web/main.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wiregate-project/wiregate/internal/web/agentclient"
	"github.com/wiregate-project/wiregate/internal/web/auth"
	webconfig "github.com/wiregate-project/wiregate/internal/web/config"
	"github.com/wiregate-project/wiregate/internal/web/httpapi"
	"github.com/wiregate-project/wiregate/internal/web/repository"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		os.Exit(resetPassword(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "check-config" {
		configFlags := flag.NewFlagSet("check-config", flag.ContinueOnError)
		configPath := configFlags.String("config", "/etc/wiregate/web.yaml", "path to web YAML config")
		if err := configFlags.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		if _, err := webconfig.Load(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, "load web config:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthFlags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
		configPath := healthFlags.String("config", "/etc/wiregate/web.yaml", "path to web YAML config")
		if err := healthFlags.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		cfg, err := webconfig.Load(*configPath)
		if err != nil || healthcheck(cfg) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap-token" {
		bootstrapFlags := flag.NewFlagSet("bootstrap-token", flag.ContinueOnError)
		configPath := bootstrapFlags.String("config", "/etc/wiregate/web.yaml", "path to web YAML config")
		ttl := bootstrapFlags.Duration("ttl", 15*time.Minute, "bootstrap token lifetime")
		if err := bootstrapFlags.Parse(os.Args[2:]); err != nil || *ttl <= 0 {
			os.Exit(2)
		}
		cfg, err := webconfig.Load(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load web config:", err)
			os.Exit(1)
		}
		store, err := repository.Open(context.Background(), cfg.DatabasePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open web database:", err)
			os.Exit(1)
		}
		defer store.Close()
		token, hash, err := auth.NewBootstrapToken()
		if err == nil {
			err = store.SetBootstrapToken(
				context.Background(), hash, time.Now().UTC().Add(*ttl), time.Now().UTC(),
			)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "create bootstrap token:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, token)
		return
	}
	configPath := flag.String("config", "/etc/wiregate/web.yaml", "path to web YAML config")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := webconfig.Load(*configPath)
	if err != nil {
		logger.Error("load web config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	webRepository, err := repository.Open(ctx, cfg.DatabasePath)
	if err != nil {
		logger.Error("open web repository", "error", err)
		os.Exit(1)
	}
	defer webRepository.Close()
	authManager, err := auth.NewManager(webRepository)
	if err != nil {
		logger.Error("create auth manager", "error", err)
		os.Exit(1)
	}

	agent, err := agentclient.New(cfg.AgentSocket)
	if err != nil {
		logger.Error("create agent client", "error", err)
		os.Exit(1)
	}
	defer agent.Close()

	api, err := httpapi.New(agent, authManager, logger)
	if err != nil {
		logger.Error("create HTTP API", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	serveErrors := make(chan error, 1)
	go func() {
		logger.Info(
			"wiregate web listening",
			"address", cfg.ListenAddress,
			"schema_version", webRepository.SchemaVersion(),
		)
		if cfg.TLSCertFile != "" {
			serveErrors <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("wiregate web shutting down")
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("web server stopped", "error", err)
		}
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful web shutdown", "error", err)
	}
}

func resetPassword(arguments []string) int {
	resetFlags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	resetFlags.SetOutput(os.Stderr)
	configPath := resetFlags.String("config", "/etc/wiregate/web.yaml", "path to web YAML config")
	username := resetFlags.String("username", "", "administrator username to recover")
	if err := resetFlags.Parse(arguments); err != nil {
		return 2
	}
	if resetFlags.NArg() != 0 || *username == "" {
		fmt.Fprintln(os.Stderr, "reset-password requires --username <admin>")
		return 2
	}
	input := int(os.Stdin.Fd())
	if !term.IsTerminal(input) {
		fmt.Fprintln(os.Stderr, "reset-password requires an interactive terminal")
		return 1
	}
	password, err := readPassword(input, "New password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read new password:", err)
		return 1
	}
	defer clear(password)
	confirmation, err := readPassword(input, "Confirm new password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "confirm new password:", err)
		return 1
	}
	defer clear(confirmation)
	if !bytes.Equal(password, confirmation) {
		fmt.Fprintln(os.Stderr, "password confirmation does not match")
		return 1
	}
	passwordHash, err := auth.HashPassword(string(password))
	if err != nil {
		fmt.Fprintln(os.Stderr, "new password rejected:", err)
		return 1
	}
	cfg, err := webconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load web config:", err)
		return 1
	}
	ctx := context.Background()
	store, err := repository.Open(ctx, cfg.DatabasePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open web database:", err)
		return 1
	}
	defer store.Close()
	storedUsername, err := store.ResetAdminPassword(ctx, *username, passwordHash, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "reset admin password:", err)
		return 1
	}
	fmt.Fprintf(
		os.Stdout,
		"Password reset for administrator %s; all existing web sessions were revoked.\n",
		storedUsername,
	)
	return 0
}

func readPassword(input int, prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(input)
	fmt.Fprintln(os.Stderr)
	return password, err
}

func healthcheck(cfg webconfig.Config) error {
	if info, err := os.Stat(cfg.DatabasePath); err != nil || !info.Mode().IsRegular() {
		return errors.New("web database is unavailable")
	}
	agent, err := net.DialTimeout("unix", cfg.AgentSocket, 2*time.Second)
	if err != nil {
		return err
	}
	_ = agent.Close()
	host, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return err
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, port)
	web, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	return web.Close()
}

// File: src/internal/agent/profile/server.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package profile

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wiregate-project/wiregate/internal/agent/validation"
)

type ServerConfig struct {
	OperationID string
	PrivateKey  []byte
	Addresses   []string
	ListenPort  uint16
	PostUp      string
	PostDown    string
}

func RenderServerConfig(config ServerConfig) ([]byte, error) {
	if strings.TrimSpace(config.OperationID) == "" || strings.ContainsAny(config.OperationID, "\r\n") {
		return nil, errors.New("operation ID is required")
	}
	privateKey := strings.TrimSpace(string(config.PrivateKey))
	if err := validation.WireGuardKey(privateKey); err != nil {
		return nil, fmt.Errorf("server private key: %w", err)
	}
	if err := validation.ListenPort(config.ListenPort); err != nil {
		return nil, err
	}
	if len(config.Addresses) == 0 {
		return nil, errors.New("at least one interface address is required")
	}
	addresses := make([]string, 0, len(config.Addresses))
	for _, value := range config.Addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid interface address %q", value)
		}
		addresses = append(addresses, prefix.String())
	}
	for _, hook := range []string{config.PostUp, config.PostDown} {
		if strings.ContainsAny(hook, "\r\n") {
			return nil, errors.New("fixed hook contains a newline")
		}
	}
	if (config.PostUp == "") != (config.PostDown == "") {
		return nil, errors.New("PostUp and PostDown must be supplied together")
	}

	var output bytes.Buffer
	output.WriteString("# WireGate-Operation: ")
	output.WriteString(config.OperationID)
	output.WriteString("\n[Interface]\nPrivateKey = ")
	output.WriteString(privateKey)
	output.WriteString("\nAddress = ")
	output.WriteString(strings.Join(addresses, ", "))
	output.WriteString("\nListenPort = ")
	output.WriteString(strconv.FormatUint(uint64(config.ListenPort), 10))
	output.WriteByte('\n')
	if config.PostUp != "" {
		output.WriteString("PostUp = ")
		output.WriteString(config.PostUp)
		output.WriteString("\nPostDown = ")
		output.WriteString(config.PostDown)
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

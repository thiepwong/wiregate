// File: src/internal/web/httpapi/ui.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package httpapi

import "embed"

//go:embed ui/*
var uiFiles embed.FS

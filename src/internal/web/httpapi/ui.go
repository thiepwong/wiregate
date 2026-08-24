// File: src/internal/web/httpapi/ui.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package httpapi

import "embed"

//go:embed ui/*
var uiFiles embed.FS

// File: src/internal/agent/artifact/test_fixture_test.go
// Project: WireGate
// Copyright (c) 2026 Thiep Wong
// SPDX-License-Identifier: MIT
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate automated tests.

package artifact_test

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/agent/inventory"
)

func inventorySnapshot() inventory.Snapshot {
	return inventory.Snapshot{
		RefreshedAt: time.Now().UTC(),
		Interfaces: []inventory.Interface{{
			Name: "wg0", Backend: "wg_quick", ConfigPresent: true,
			Peers: []inventory.Peer{{
				Name: "peer", PublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
				AllowedIPs: []string{"10.0.0.2/32"},
			}},
		}},
	}
}

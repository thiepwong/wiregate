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

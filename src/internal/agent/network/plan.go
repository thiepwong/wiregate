// File: src/internal/agent/network/plan.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package network

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/wiregate-project/wiregate/internal/agent/validation"
)

type Profile string

const (
	ProfileServerOnly Profile = "server_only"
	ProfileLAN        Profile = "lan"
	ProfileFullTunnel Profile = "full_tunnel"
)

type FirewallMode string

const (
	FirewallManagedNFT FirewallMode = "managed_nft"
	FirewallExternal   FirewallMode = "external"
)

type PlanInput struct {
	InterfaceID   string
	InterfaceName string
	Profile       Profile
	FirewallMode  FirewallMode
	ListenPort    uint16
	TunnelCIDRs   []string
	LANCIDRs      []string
	EgressDevice  string
	EnableIPv6    bool
}

type Plan struct {
	TableName         string
	ClientRoutes      []string
	UpNFT             []byte
	DownNFT           []byte
	Sysctl            []byte
	PostUp            string
	PostDown          string
	ExternalChecklist []string
}

var devicePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func BuildPlan(input PlanInput) (Plan, error) {
	if err := validation.InterfaceName(input.InterfaceName); err != nil {
		return Plan{}, err
	}
	if err := validation.ListenPort(input.ListenPort); err != nil {
		return Plan{}, err
	}
	if input.Profile != ProfileServerOnly && input.Profile != ProfileLAN && input.Profile != ProfileFullTunnel {
		return Plan{}, errors.New("unsupported deployment profile")
	}
	if input.FirewallMode != FirewallManagedNFT && input.FirewallMode != FirewallExternal {
		return Plan{}, errors.New("unsupported firewall mode")
	}
	tunnels, err := validation.CanonicalPrefixes(input.TunnelCIDRs)
	if err != nil || len(tunnels) == 0 {
		return Plan{}, errors.New("at least one valid tunnel CIDR is required")
	}
	lan, err := validation.CanonicalPrefixes(input.LANCIDRs)
	if err != nil {
		return Plan{}, err
	}
	if input.Profile == ProfileLAN && len(lan) == 0 {
		return Plan{}, errors.New("LAN profile requires at least one LAN CIDR")
	}
	if (input.Profile == ProfileLAN || input.Profile == ProfileFullTunnel) &&
		!devicePattern.MatchString(input.EgressDevice) {
		return Plan{}, errors.New("forwarding profile requires a valid egress device")
	}

	shortID := strings.ReplaceAll(input.InterfaceID, "-", "")
	if len(shortID) < 12 {
		return Plan{}, errors.New("interface ID is too short for deterministic firewall ownership")
	}
	table := "wiregate_" + strings.ToLower(shortID[:12])
	plan := Plan{TableName: table}
	switch input.Profile {
	case ProfileServerOnly:
		for _, value := range input.TunnelCIDRs {
			tunnel, parseErr := netip.ParsePrefix(strings.TrimSpace(value))
			if parseErr != nil {
				return Plan{}, parseErr
			}
			bits := 128
			if tunnel.Addr().Is4() {
				bits = 32
			}
			plan.ClientRoutes = append(plan.ClientRoutes, netip.PrefixFrom(tunnel.Addr(), bits).String())
		}
	case ProfileLAN:
		for _, prefix := range lan {
			plan.ClientRoutes = append(plan.ClientRoutes, prefix.String())
		}
	case ProfileFullTunnel:
		plan.ClientRoutes = append(plan.ClientRoutes, "0.0.0.0/0")
		if input.EnableIPv6 {
			plan.ClientRoutes = append(plan.ClientRoutes, "::/0")
		}
	}

	if input.Profile != ProfileServerOnly {
		plan.Sysctl = []byte("net.ipv4.ip_forward=1\n")
		if input.EnableIPv6 {
			plan.Sysctl = append(plan.Sysctl, []byte("net.ipv6.conf.all.forwarding=1\n")...)
		}
	}
	if input.FirewallMode == FirewallExternal {
		plan.ExternalChecklist = externalChecklist(input, tunnels, lan)
		return plan, nil
	}
	plan.UpNFT = renderUpNFT(input, table, tunnels, lan)
	plan.DownNFT = []byte("destroy table inet " + table + "\n")
	networkRoot := "/etc/wiregate/network/" + input.InterfaceName
	plan.PostUp = "/usr/sbin/nft -f " + networkRoot + "/up.nft"
	plan.PostDown = "/usr/sbin/nft -f " + networkRoot + "/down.nft"
	return plan, nil
}

func RejectNetworkOverlap(candidate []netip.Prefix, occupied []netip.Prefix) error {
	for _, proposed := range candidate {
		for _, current := range occupied {
			if proposed.Addr().BitLen() == current.Addr().BitLen() && proposed.Overlaps(current) {
				return fmt.Errorf("tunnel CIDR %s overlaps host/network prefix %s", proposed, current)
			}
		}
	}
	return nil
}

func renderUpNFT(input PlanInput, table string, tunnels, lan []netip.Prefix) []byte {
	var output strings.Builder
	output.WriteString("destroy table inet ")
	output.WriteString(table)
	output.WriteString("\n")
	output.WriteString("table inet ")
	output.WriteString(table)
	output.WriteString(" {\n")
	output.WriteString("  chain input {\n")
	output.WriteString("    type filter hook input priority -10; policy accept;\n")
	output.WriteString("    udp dport ")
	output.WriteString(strconv.FormatUint(uint64(input.ListenPort), 10))
	output.WriteString(" accept comment \"wiregate-owned\"\n")
	output.WriteString("  }\n")
	if input.Profile != ProfileServerOnly {
		output.WriteString("  chain forward {\n")
		output.WriteString("    type filter hook forward priority -10; policy accept;\n")
		output.WriteString("    ct state established,related accept comment \"wiregate-owned\"\n")
		for _, tunnel := range tunnels {
			family := "ip"
			if tunnel.Addr().Is6() {
				family = "ip6"
			}
			output.WriteString("    iifname \"")
			output.WriteString(input.InterfaceName)
			output.WriteString("\" ")
			output.WriteString(family)
			output.WriteString(" saddr ")
			output.WriteString(tunnel.String())
			output.WriteString(" accept comment \"wiregate-owned\"\n")
		}
		output.WriteString("  }\n")
	}
	if input.Profile == ProfileFullTunnel {
		output.WriteString("  chain postrouting {\n")
		output.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
		for _, tunnel := range tunnels {
			family := "ip"
			if tunnel.Addr().Is6() {
				family = "ip6"
			}
			output.WriteString("    ")
			output.WriteString(family)
			output.WriteString(" saddr ")
			output.WriteString(tunnel.String())
			output.WriteString(" oifname \"")
			output.WriteString(input.EgressDevice)
			output.WriteString("\" masquerade comment \"wiregate-owned\"\n")
		}
		output.WriteString("  }\n")
	}
	output.WriteString("}\n")
	return []byte(output.String())
}

func externalChecklist(input PlanInput, tunnels, lan []netip.Prefix) []string {
	checklist := []string{
		"Allow UDP destination port " + strconv.FormatUint(uint64(input.ListenPort), 10) + " on the gateway input path.",
	}
	if input.Profile != ProfileServerOnly {
		checklist = append(checklist,
			"Enable stateful forwarding from "+input.InterfaceName+" to "+input.EgressDevice+".",
			"Allow established and related return traffic back to "+input.InterfaceName+".",
		)
	}
	for _, prefix := range tunnels {
		checklist = append(checklist, "Allow tunnel source CIDR "+prefix.String()+".")
	}
	for _, prefix := range lan {
		checklist = append(checklist, "Provide a return route for "+prefix.String()+" where applicable.")
	}
	if input.Profile == ProfileFullTunnel {
		checklist = append(checklist, "Masquerade tunnel CIDRs only on egress device "+input.EgressDevice+".")
	}
	sort.Strings(checklist)
	return checklist
}

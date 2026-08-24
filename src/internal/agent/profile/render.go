package profile

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wiregate-project/wiregate/internal/agent/validation"
)

type ClientConfig struct {
	PrivateKey          []byte
	Addresses           []string
	DNS                 []string
	MTU                 uint16
	ServerPublicKey     string
	PresharedKey        []byte
	EndpointHost        string
	EndpointPort        uint16
	Routes              []string
	PersistentKeepalive uint16
}

func RenderClientConfig(config ClientConfig) ([]byte, error) {
	privateKey := strings.TrimSpace(string(config.PrivateKey))
	if err := validation.WireGuardKey(privateKey); err != nil {
		return nil, fmt.Errorf("client private key: %w", err)
	}
	if err := validation.WireGuardKey(config.ServerPublicKey); err != nil {
		return nil, fmt.Errorf("server public key: %w", err)
	}
	if len(config.PresharedKey) != 0 {
		if err := validation.WireGuardKey(strings.TrimSpace(string(config.PresharedKey))); err != nil {
			return nil, fmt.Errorf("preshared key: %w", err)
		}
	}
	if len(config.Addresses) == 0 {
		return nil, errors.New("at least one client tunnel address is required")
	}
	addresses := make([]string, 0, len(config.Addresses))
	for _, value := range config.Addresses {
		prefix, err := validation.TunnelAddress(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, prefix.String())
	}
	if len(config.Routes) == 0 {
		return nil, errors.New("at least one client route is required")
	}
	routes, err := validation.CanonicalPrefixes(config.Routes)
	if err != nil {
		return nil, err
	}
	if err := validation.EndpointHost(config.EndpointHost); err != nil {
		return nil, err
	}
	if err := validation.ListenPort(config.EndpointPort); err != nil {
		return nil, fmt.Errorf("endpoint port: %w", err)
	}
	if err := validation.MTU(config.MTU); err != nil {
		return nil, err
	}
	if err := validation.DNS(config.DNS); err != nil {
		return nil, err
	}

	var output bytes.Buffer
	output.WriteString("[Interface]\n")
	output.WriteString("PrivateKey = ")
	output.WriteString(privateKey)
	output.WriteByte('\n')
	output.WriteString("Address = ")
	output.WriteString(strings.Join(addresses, ", "))
	output.WriteByte('\n')
	if len(config.DNS) > 0 {
		output.WriteString("DNS = ")
		for index, value := range config.DNS {
			if index > 0 {
				output.WriteString(", ")
			}
			address, _ := netip.ParseAddr(strings.TrimSpace(value))
			output.WriteString(address.String())
		}
		output.WriteByte('\n')
	}
	if config.MTU != 0 {
		output.WriteString("MTU = ")
		output.WriteString(strconv.FormatUint(uint64(config.MTU), 10))
		output.WriteByte('\n')
	}
	output.WriteByte('\n')
	output.WriteString("[Peer]\n")
	output.WriteString("PublicKey = ")
	output.WriteString(strings.TrimSpace(config.ServerPublicKey))
	output.WriteByte('\n')
	if len(config.PresharedKey) > 0 {
		output.WriteString("PresharedKey = ")
		output.WriteString(strings.TrimSpace(string(config.PresharedKey)))
		output.WriteByte('\n')
	}
	output.WriteString("Endpoint = ")
	output.WriteString(endpoint(config.EndpointHost, config.EndpointPort))
	output.WriteByte('\n')
	output.WriteString("AllowedIPs = ")
	for index, route := range routes {
		if index > 0 {
			output.WriteString(", ")
		}
		output.WriteString(route.String())
	}
	output.WriteByte('\n')
	if config.PersistentKeepalive != 0 {
		output.WriteString("PersistentKeepalive = ")
		output.WriteString(strconv.FormatUint(uint64(config.PersistentKeepalive), 10))
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func endpoint(host string, port uint16) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if address := net.ParseIP(host); address != nil && strings.Contains(host, ":") {
		return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}
	return host + ":" + strconv.FormatUint(uint64(port), 10)
}

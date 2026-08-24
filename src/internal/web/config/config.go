package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddress string `yaml:"listen_address"`
	AgentSocket   string `yaml:"agent_socket"`
	DatabasePath  string `yaml:"database_path"`
	TLSCertFile   string `yaml:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file"`
}

func Defaults() Config {
	return Config{
		ListenAddress: "127.0.0.1:8443",
		AgentSocket:   "/run/wiregate/agent.sock",
		DatabasePath:  "/var/lib/wiregate-web/web.db",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return Config{}, errors.New("web config path is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read web config: %w", err)
	}
	if len(body) > 1<<20 {
		return Config{}, errors.New("web config exceeds 1 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode web config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("web config must contain exactly one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	host, rawPort, listenErr := net.SplitHostPort(c.ListenAddress)
	port, portErr := strconv.ParseUint(rawPort, 10, 16)
	switch {
	case c.ListenAddress == "":
		return errors.New("listen_address is required")
	case listenErr != nil || portErr != nil || port == 0:
		return errors.New("listen_address must be a TCP host:port with a non-zero port")
	case !filepath.IsAbs(c.AgentSocket):
		return errors.New("agent_socket must be absolute")
	case !filepath.IsAbs(c.DatabasePath):
		return errors.New("database_path must be absolute")
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		return errors.New("tls_cert_file and tls_key_file must be configured together")
	case c.TLSCertFile != "" &&
		(!filepath.IsAbs(c.TLSCertFile) || !filepath.IsAbs(c.TLSKeyFile)):
		return errors.New("TLS certificate and key paths must be absolute")
	case c.TLSCertFile == "" && !loopbackHost(host):
		return errors.New("TLS is required when listen_address is not loopback")
	}
	return nil
}

func loopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

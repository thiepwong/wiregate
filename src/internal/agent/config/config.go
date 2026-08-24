package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)
	gatewayIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Config struct {
	GatewayID            string        `yaml:"gateway_id"`
	SocketPath           string        `yaml:"socket_path"`
	DatabasePath         string        `yaml:"database_path"`
	KeyDir               string        `yaml:"key_dir"`
	WireGuardConfigDir   string        `yaml:"wireguard_config_dir"`
	AllowedInterfaces    []string      `yaml:"allowed_interfaces"`
	AllowedPeerUID       int           `yaml:"allowed_peer_uid"`
	AllowedPeerGID       int           `yaml:"allowed_peer_gid"`
	RuntimePollInterval  time.Duration `yaml:"runtime_poll_interval"`
	FileScanInterval     time.Duration `yaml:"file_scan_interval"`
	OperationTimeout     time.Duration `yaml:"operation_timeout"`
	ArtifactTTL          time.Duration `yaml:"artifact_ttl"`
	IPQuarantineDuration time.Duration `yaml:"ip_quarantine_duration"`
}

func Defaults() Config {
	return Config{
		SocketPath:           "/run/wiregate/agent.sock",
		DatabasePath:         "/var/lib/wiregate-agent/agent.db",
		KeyDir:               "/etc/wiregate/keys",
		WireGuardConfigDir:   "/etc/wireguard",
		AllowedInterfaces:    []string{"*"},
		AllowedPeerUID:       -1,
		AllowedPeerGID:       -1,
		RuntimePollInterval:  5 * time.Second,
		FileScanInterval:     30 * time.Second,
		OperationTimeout:     30 * time.Second,
		ArtifactTTL:          10 * time.Minute,
		IPQuarantineDuration: 24 * time.Hour,
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return Config{}, errors.New("agent config path is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read agent config: %w", err)
	}
	if len(body) > 1<<20 {
		return Config{}, errors.New("agent config exceeds 1 MiB")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode agent config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("agent config must contain exactly one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	switch {
	case !gatewayIDPattern.MatchString(c.GatewayID):
		return errors.New("gateway_id must be a lowercase UUIDv7")
	case !filepath.IsAbs(c.SocketPath):
		return errors.New("socket_path must be absolute")
	case !filepath.IsAbs(c.DatabasePath):
		return errors.New("database_path must be absolute")
	case !filepath.IsAbs(c.KeyDir):
		return errors.New("key_dir must be absolute")
	case !filepath.IsAbs(c.WireGuardConfigDir):
		return errors.New("wireguard_config_dir must be absolute")
	case len(c.AllowedInterfaces) == 0:
		return errors.New("allowed_interfaces cannot be empty")
	case c.RuntimePollInterval <= 0:
		return errors.New("runtime_poll_interval must be positive")
	case c.FileScanInterval <= 0:
		return errors.New("file_scan_interval must be positive")
	case c.OperationTimeout <= 0:
		return errors.New("operation_timeout must be positive")
	case c.ArtifactTTL <= 0:
		return errors.New("artifact_ttl must be positive")
	case c.IPQuarantineDuration < 0:
		return errors.New("ip_quarantine_duration cannot be negative")
	}
	for _, name := range c.AllowedInterfaces {
		if name != "*" && !interfaceNamePattern.MatchString(name) {
			return fmt.Errorf("invalid allowed interface %q", name)
		}
	}
	if c.AllowedPeerUID < 0 || c.AllowedPeerGID < 0 {
		return errors.New("allowed peer uid/gid must identify the exact web process")
	}
	return nil
}

func (c Config) AllowsInterface(name string) bool {
	if !interfaceNamePattern.MatchString(name) {
		return false
	}
	for _, allowed := range c.AllowedInterfaces {
		if allowed == "*" || allowed == name {
			return true
		}
	}
	return false
}

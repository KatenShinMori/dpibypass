package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Supported configuration version.
const CurrentVersion = 1

// Default settings.
const (
	DefaultListen              = "127.0.0.1:1080"
	DefaultProfile             = "none"
	DefaultLogLevel            = "info"
	DefaultDialTimeoutMS       = 8000
	DefaultInspectionTimeoutMS = 1000
	DefaultIdleTimeoutS        = 120
	DefaultMaxConnections      = 1000
	DefaultMaxInitialBytes     = 65536
)

// Supported engine modes.
const (
	ModeProxy  = "proxy"
	ModePacket = "packet"
)

// Default Phase 2 packet settings.
const (
	DefaultPacketMode               = ModeProxy
	DefaultPacketFakeMode           = "none"
	DefaultPacketFakeTTL            = 4
	DefaultPacketFakeSNI            = "www.example.com"
	DefaultPacketFakeDelayMS        = 0
	DefaultPacketSplitOffset        = "sni-mid"
	DefaultPacketInterPacketDelayMS = 0
)

// PacketConfig specifies Phase 2 wire-level packet interception and evasion parameters.
type PacketConfig struct {
	FakePacketMode     string `json:"fake_mode,omitempty"`
	FakeTTL            int    `json:"fake_ttl,omitempty"`
	FakeSNI            string `json:"fake_sni,omitempty"`
	FakeDelayMS        int    `json:"fake_delay_ms,omitempty"`
	SplitOffset        string `json:"split_offset,omitempty"`
	InterPacketDelayMS int    `json:"inter_packet_delay_ms,omitempty"`
	DropQUIC           *bool  `json:"drop_quic,omitempty"`
	DesyncHTTP         *bool  `json:"desync_http,omitempty"`
	InterceptDNS       *bool  `json:"intercept_dns,omitempty"`
	AutoLearn          *bool  `json:"auto_learn,omitempty"`
	AutoLearnPath      string `json:"auto_learn_path,omitempty"`
}

// DropQUICOrDefault returns true unless DropQUIC is explicitly configured to false.
func (p PacketConfig) DropQUICOrDefault() bool {
	if p.DropQUIC == nil {
		return true
	}
	return *p.DropQUIC
}

// DesyncHTTPOrDefault returns true unless DesyncHTTP is explicitly configured to false.
func (p PacketConfig) DesyncHTTPOrDefault() bool {
	if p.DesyncHTTP == nil {
		return true
	}
	return *p.DesyncHTTP
}

// InterceptDNSOrDefault returns true if InterceptDNS is explicitly configured to true.
func (p PacketConfig) InterceptDNSOrDefault() bool {
	if p.InterceptDNS == nil {
		return false
	}
	return *p.InterceptDNS
}

// AutoLearnOrDefault returns true unless AutoLearn is explicitly configured to false.
func (p PacketConfig) AutoLearnOrDefault() bool {
	if p.AutoLearn == nil {
		return true
	}
	return *p.AutoLearn
}

// Config represents the top-level dpibypass configuration structure.
type Config struct {
	Version        int                      `json:"version"`
	Mode           string                   `json:"mode,omitempty"`
	Listen         string                   `json:"listen"`
	DefaultProfile string                   `json:"default_profile"`
	DoH            DoHConfig                `json:"doh"`
	Profiles       map[string]ProfileConfig `json:"profiles"`
	DomainRules    []DomainRuleConfig       `json:"domain_rules"`
	Timeouts       TimeoutsConfig           `json:"timeouts"`
	Limits         LimitsConfig             `json:"limits"`
	LogLevel       string                   `json:"log_level"`
	Packet         PacketConfig             `json:"packet,omitempty"`
}

// DoHConfig defines optional DNS-over-HTTPS settings.
type DoHConfig struct {
	Enabled        bool          `json:"enabled"`
	FallbackSystem bool          `json:"fallback_system"`
	Endpoints      []DoHEndpoint `json:"endpoints"`
}

// DoHEndpoint defines an individual DoH resolver endpoint.
type DoHEndpoint struct {
	URL          string   `json:"url"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}

// ProfileConfig defines strategy parameters for a profile name.
type ProfileConfig struct {
	Type            string   `json:"type"`
	Offset          string   `json:"offset,omitempty"`
	RecordOffset    string   `json:"record_offset,omitempty"`
	WriteOffset     string   `json:"write_offset,omitempty"`
	DelayMS         int      `json:"delay_ms,omitempty"`
	ChunkSize       int      `json:"chunk_size,omitempty"`
	MaxChunks       int      `json:"max_chunks,omitempty"`
	HostHeaderTweak string   `json:"host_header_tweak,omitempty"`
	Pipeline        []string `json:"pipeline,omitempty"`
}

// DomainRuleConfig maps a domain or wildcard match pattern to a profile.
type DomainRuleConfig struct {
	Match   string `json:"match"`
	Profile string `json:"profile"`
}

// TimeoutsConfig specifies network and inspection deadlines.
type TimeoutsConfig struct {
	DialMS              int `json:"dial_ms"`
	InitialInspectionMS int `json:"initial_inspection_ms"`
	IdleS               int `json:"idle_s"`
	ShutdownGraceMS     int `json:"shutdown_grace_ms,omitempty"`
}

// LimitsConfig specifies resource bounds for safety.
type LimitsConfig struct {
	MaxConnections  int `json:"max_connections"`
	MaxInitialBytes int `json:"max_initial_bytes"`
}

// DefaultConfig returns a safe, loopback-only configuration baseline.
func DefaultConfig() *Config {
	dropQUIC := true
	interceptDNS := false
	autoLearn := true
	return &Config{
		Version:        CurrentVersion,
		Mode:           DefaultPacketMode,
		Listen:         DefaultListen,
		DefaultProfile: DefaultProfile,
		DoH: DoHConfig{
			Enabled:        false,
			FallbackSystem: true,
			Endpoints: []DoHEndpoint{
				{
					URL:          "https://cloudflare-dns.com/dns-query",
					BootstrapIPs: []string{"1.1.1.1", "1.0.0.1"},
				},
				{
					URL:          "https://dns.google/dns-query",
					BootstrapIPs: []string{"8.8.8.8", "8.8.4.4"},
				},
			},
		},
		Profiles: map[string]ProfileConfig{
			"none": {
				Type: "none",
			},
		},
		DomainRules: []DomainRuleConfig{},
		Timeouts: TimeoutsConfig{
			DialMS:              DefaultDialTimeoutMS,
			InitialInspectionMS: DefaultInspectionTimeoutMS,
			IdleS:               DefaultIdleTimeoutS,
		},
		Limits: LimitsConfig{
			MaxConnections:  DefaultMaxConnections,
			MaxInitialBytes: DefaultMaxInitialBytes,
		},
		LogLevel: DefaultLogLevel,
		Packet: PacketConfig{
			FakePacketMode:     DefaultPacketFakeMode,
			FakeTTL:            DefaultPacketFakeTTL,
			FakeSNI:            DefaultPacketFakeSNI,
			FakeDelayMS:        DefaultPacketFakeDelayMS,
			SplitOffset:        DefaultPacketSplitOffset,
			InterPacketDelayMS: DefaultPacketInterPacketDelayMS,
			DropQUIC:           &dropQUIC,
			InterceptDNS:       &interceptDNS,
			AutoLearn:          &autoLearn,
			AutoLearnPath:      "autolearn.json",
		},
	}
}

// Load reads and parses a JSON configuration file from disk, validating all fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config JSON: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Validate performs strict bounds checking and loopback safety enforcement.
func (c *Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("invalid version %d; expected %d", c.Version, CurrentVersion)
	}

	// Validate mode
	normMode := strings.ToLower(strings.TrimSpace(c.Mode))
	if normMode == "" {
		normMode = ModeProxy
	}
	switch normMode {
	case ModeProxy, ModePacket:
		c.Mode = normMode
	default:
		return fmt.Errorf("invalid mode %q; must be 'proxy' or 'packet'", c.Mode)
	}

	// Strictly enforce loopback address 127.0.0.1 for safety.
	host, portStr, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address format %q: %w", c.Listen, err)
	}
	if host != "127.0.0.1" {
		return fmt.Errorf("listen host %q rejected; must be strictly 127.0.0.1 for loopback safety", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid listen port %q; must be between 0 and 65535", portStr)
	}

	// Validate profiles map
	if c.Profiles == nil || len(c.Profiles) == 0 {
		return errors.New("profiles map cannot be empty; must include 'none'")
	}
	noneProf, ok := c.Profiles["none"]
	if !ok {
		return errors.New("mandatory fallback profile 'none' missing from profiles")
	}
	if strings.ToLower(strings.TrimSpace(noneProf.Type)) != "none" {
		return fmt.Errorf("mandatory profile 'none' must have type 'none', got %q", noneProf.Type)
	}
	if _, ok := c.Profiles[c.DefaultProfile]; !ok {
		return fmt.Errorf("default_profile %q not found in declared profiles", c.DefaultProfile)
	}

	for name, prof := range c.Profiles {
		normType := strings.ToLower(strings.TrimSpace(prof.Type))
		switch normType {
		case "none", "packet", "tcp-write-split", "multi-write-split", "tls-record-split", "tls-record-then-write-split", "http-host-tweak":
		default:
			return fmt.Errorf("profile %q has unsupported type %q", name, prof.Type)
		}

		if prof.DelayMS < 0 || prof.DelayMS > 10000 {
			return fmt.Errorf("profile %q delay_ms %d out of bounds (0..10000 ms)", name, prof.DelayMS)
		}
		if prof.ChunkSize < 0 || prof.ChunkSize > 65536 {
			return fmt.Errorf("profile %q chunk_size %d out of bounds (0..65536 bytes)", name, prof.ChunkSize)
		}
		if prof.MaxChunks < 0 || prof.MaxChunks > 32 {
			return fmt.Errorf("profile %q max_chunks %d out of bounds (0..32)", name, prof.MaxChunks)
		}

		if prof.Offset != "" {
			if err := validateOffsetField(name, "offset", prof.Offset); err != nil {
				return err
			}
		}

		if prof.RecordOffset != "" {
			if normType != "tls-record-then-write-split" {
				return fmt.Errorf("profile %q: record_offset is only supported for 'tls-record-then-write-split'", name)
			}
			if err := validateOffsetField(name, "record_offset", prof.RecordOffset); err != nil {
				return err
			}
		}

		if prof.WriteOffset != "" {
			if normType != "tls-record-then-write-split" {
				return fmt.Errorf("profile %q: write_offset is only supported for 'tls-record-then-write-split'", name)
			}
			if err := validateOffsetField(name, "write_offset", prof.WriteOffset); err != nil {
				return err
			}
		}

		if prof.HostHeaderTweak != "" {
			tweak := strings.ToLower(strings.TrimSpace(prof.HostHeaderTweak))
			switch tweak {
			case "lowercase", "space", "split":
			default:
				return fmt.Errorf("profile %q has invalid host_header_tweak %q; expected 'lowercase', 'space', or 'split'", name, prof.HostHeaderTweak)
			}
		}
	}

	// Validate domain rules
	if len(c.DomainRules) > 0 {
		if _, err := NewDomainMatcher(c.DomainRules); err != nil {
			return fmt.Errorf("invalid domain_rules: %w", err)
		}
		for i, r := range c.DomainRules {
			if _, ok := c.Profiles[r.Profile]; !ok {
				return fmt.Errorf("domain rule %d (match %q) references undefined profile %q", i, r.Match, r.Profile)
			}
		}
	}

	// Validate DoH settings
	if c.DoH.Enabled && len(c.DoH.Endpoints) == 0 {
		return errors.New("doh is enabled but endpoints list is empty")
	}
	for i, ep := range c.DoH.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("doh endpoint %d has invalid URL %q; must be a valid https URL", i, ep.URL)
		}
		isIP := net.ParseIP(u.Hostname()) != nil
		if !isIP && len(ep.BootstrapIPs) == 0 {
			return fmt.Errorf("doh endpoint %d (%q) has hostname %q but no bootstrap_ips; every hostname-based DoH endpoint must have explicitly configured bootstrap IPs", i, ep.URL, u.Hostname())
		}
		for j, ipStr := range ep.BootstrapIPs {
			if net.ParseIP(ipStr) == nil {
				return fmt.Errorf("doh endpoint %d has invalid bootstrap IP %d: %q", i, j, ipStr)
			}
		}
	}

	// Validate timeouts
	if c.Timeouts.DialMS <= 0 || c.Timeouts.DialMS > 60000 {
		return fmt.Errorf("dial_ms %d out of bounds (1..60000 ms)", c.Timeouts.DialMS)
	}
	if c.Timeouts.InitialInspectionMS <= 0 || c.Timeouts.InitialInspectionMS > 10000 {
		return fmt.Errorf("initial_inspection_ms %d out of bounds (1..10000 ms)", c.Timeouts.InitialInspectionMS)
	}
	if c.Timeouts.IdleS <= 0 || c.Timeouts.IdleS > 3600 {
		return fmt.Errorf("idle_s %d out of bounds (1..3600 s)", c.Timeouts.IdleS)
	}
	if c.Timeouts.ShutdownGraceMS < 0 || c.Timeouts.ShutdownGraceMS > 60000 {
		return fmt.Errorf("shutdown_grace_ms %d out of bounds (0..60000 ms)", c.Timeouts.ShutdownGraceMS)
	}

	// Validate limits
	if c.Limits.MaxConnections <= 0 || c.Limits.MaxConnections > 100000 {
		return fmt.Errorf("max_connections %d out of bounds (1..100000)", c.Limits.MaxConnections)
	}
	if c.Limits.MaxInitialBytes < 512 || c.Limits.MaxInitialBytes > 1048576 {
		return fmt.Errorf("max_initial_bytes %d out of bounds (512..1048576 bytes)", c.Limits.MaxInitialBytes)
	}

	// Validate log level
	normalizedLevel := strings.ToLower(strings.TrimSpace(c.LogLevel))
	switch normalizedLevel {
	case "debug", "info", "warn", "error":
		c.LogLevel = normalizedLevel
	default:
		return fmt.Errorf("invalid log_level %q; must be one of: debug, info, warn, error", c.LogLevel)
	}

	// Validate Phase 2 packet configuration
	if c.Packet.FakePacketMode != "" {
		if err := validateFakePacketMode(c.Packet.FakePacketMode); err != nil {
			return fmt.Errorf("packet.fake_mode: %w", err)
		}
	}
	if c.Packet.FakeTTL != 0 {
		if c.Packet.FakeTTL < 2 || c.Packet.FakeTTL > 16 {
			return fmt.Errorf("packet.fake_ttl %d out of bounds (2..16)", c.Packet.FakeTTL)
		}
	}
	if c.Packet.FakeSNI != "" {
		sni := strings.TrimSpace(c.Packet.FakeSNI)
		if sni == "" || len(sni) > 253 || strings.ContainsAny(sni, " \t\r\n/\\:") {
			return fmt.Errorf("packet.fake_sni %q is invalid; must be a valid FQDN (max 253 characters without whitespace or path separators)", c.Packet.FakeSNI)
		}
	}
	if c.Packet.FakeDelayMS < 0 || c.Packet.FakeDelayMS > 10000 {
		return fmt.Errorf("packet.fake_delay_ms %d out of bounds (0..10000 ms)", c.Packet.FakeDelayMS)
	}
	if c.Packet.SplitOffset != "" {
		if err := validateOffsetField("packet", "split_offset", c.Packet.SplitOffset); err != nil {
			return err
		}
	}
	if c.Packet.InterPacketDelayMS < 0 || c.Packet.InterPacketDelayMS > 10000 {
		return fmt.Errorf("packet.inter_packet_delay_ms %d out of bounds (0..10000 ms)", c.Packet.InterPacketDelayMS)
	}

	return nil
}

// validateFakePacketMode checks that the fake packet mode string contains only valid tokens.
func validateFakePacketMode(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	tokens := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == '+' || r == ',' || r == '|'
	})
	if len(tokens) == 0 {
		return nil
	}
	for _, tok := range tokens {
		t := strings.ToLower(strings.TrimSpace(tok))
		switch t {
		case "none", "off", "disabled":
		case "ttl", "multi-ttl", "ttl-auto":
		case "wrong-chksum", "bad-chksum", "wrong-checksum", "bad-checksum":
		case "both":
		default:
			return fmt.Errorf("unsupported fake packet mode %q; expected 'none', 'ttl', 'multi-ttl', 'wrong-chksum', or 'both'", tok)
		}
	}
	return nil
}

// validateOffsetField ensures an offset specification is 'sni-start', 'sni-mid', 'sni-end', or a positive integer.
func validateOffsetField(profileName, fieldName, rawVal string) error {
	off := strings.ToLower(strings.TrimSpace(rawVal))
	switch off {
	case "sni-start", "sni-mid", "sni-end":
		return nil
	default:
		val, err := strconv.Atoi(off)
		if err != nil || val <= 0 {
			return fmt.Errorf("profile %q has invalid %s %q; expected 'sni-start', 'sni-mid', 'sni-end', or positive integer", profileName, fieldName, rawVal)
		}
		return nil
	}
}

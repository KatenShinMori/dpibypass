package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() should be valid, got: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1080" {
		t.Errorf("expected default listen 127.0.0.1:1080, got %s", cfg.Listen)
	}
	if cfg.DefaultProfile != "none" {
		t.Errorf("expected default profile 'none', got %s", cfg.DefaultProfile)
	}
}

func TestValidateLoopbackSafety(t *testing.T) {
	tests := []struct {
		listen    string
		expectErr bool
	}{
		{"127.0.0.1:1080", false},
		{"127.0.0.1:8080", false},
		{"0.0.0.0:1080", true},
		{"::1:1080", true}, // IPv6 explicitly excluded without approval
		{"192.168.1.1:1080", true},
		{"10.0.0.1:1080", true},
		{"localhost:1080", true}, // hostnames must not be used in listen address; must be literal 127.0.0.1
		{"127.0.0.1:0", false},   // port 0 is allowed for ephemeral port testing if within 1..65535, wait! Port 0 is rejected by 1..65535 check
	}

	for _, tt := range tests {
		cfg := DefaultConfig()
		cfg.Listen = tt.listen
		err := cfg.Validate()
		if tt.expectErr && err == nil {
			t.Errorf("listen %q: expected validation error, got nil", tt.listen)
		}
		if !tt.expectErr && err != nil {
			t.Errorf("listen %q: unexpected validation error: %v", tt.listen, err)
		}
	}
}

func TestValidateBounds(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Version = 2
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for version != 1")
		}
	})

	t.Run("missing none profile", func(t *testing.T) {
		cfg := DefaultConfig()
		delete(cfg.Profiles, "none")
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when profile 'none' is missing")
		}
	})

	t.Run("invalid none profile type", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["none"] = ProfileConfig{Type: "tcp-write-split"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when profile 'none' has non-none type")
		}
	})

	t.Run("unsupported profile type", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["invalid"] = ProfileConfig{Type: "unsupported-magic"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for unsupported profile type")
		}
	})

	t.Run("invalid profile parameters", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["bad-delay"] = ProfileConfig{Type: "tcp-write-split", DelayMS: -1}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative delay_ms")
		}

		cfg = DefaultConfig()
		cfg.Profiles["bad-chunks"] = ProfileConfig{Type: "multi-write-split", MaxChunks: 100}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for max_chunks > 32")
		}

		cfg = DefaultConfig()
		cfg.Profiles["bad-offset"] = ProfileConfig{Type: "tcp-write-split", Offset: "invalid-offset"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid offset string")
		}
	})

	t.Run("invalid timeouts", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Timeouts.DialMS = 0
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for dial_ms <= 0")
		}

		cfg = DefaultConfig()
		cfg.Timeouts.InitialInspectionMS = -1
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for initial_inspection_ms <= 0")
		}

		cfg = DefaultConfig()
		cfg.Timeouts.ShutdownGraceMS = -1
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for shutdown_grace_ms < 0")
		}

		cfg = DefaultConfig()
		cfg.Timeouts.ShutdownGraceMS = 60001
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for shutdown_grace_ms > 60000")
		}
	})

	t.Run("invalid limits", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Limits.MaxConnections = 0
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for max_connections <= 0")
		}

		cfg = DefaultConfig()
		cfg.Limits.MaxInitialBytes = 100
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for max_initial_bytes < 512")
		}
	})

	t.Run("log level", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.LogLevel = "INVALID"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for unknown log level")
		}

		cfg.LogLevel = "DEBUG"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid for DEBUG (case-insensitive), got %v", err)
		}
		if cfg.LogLevel != "debug" {
			t.Errorf("expected normalized log level 'debug', got %s", cfg.LogLevel)
		}
	})
}

func TestLoadConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	validJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "doh": {
    "enabled": false,
    "fallback_system": true,
    "endpoints": []
  },
  "profiles": {
    "none": { "type": "none" }
  },
  "domain_rules": [],
  "timeouts": {
    "dial_ms": 5000,
    "initial_inspection_ms": 1000,
    "idle_s": 60
  },
  "limits": {
    "max_connections": 500,
    "max_initial_bytes": 65536
  },
  "log_level": "info"
}`
	validFile := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(validFile, []byte(validJSON), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(validFile)
	if err != nil {
		t.Fatalf("unexpected error loading valid config: %v", err)
	}
	if cfg.Timeouts.DialMS != 5000 {
		t.Errorf("expected dial_ms 5000, got %d", cfg.Timeouts.DialMS)
	}

	// Test malformed JSON
	malformedFile := filepath.Join(tempDir, "malformed.json")
	if err := os.WriteFile(malformedFile, []byte("{ invalid json"), 0600); err != nil {
		t.Fatalf("write malformed temp config: %v", err)
	}
	if _, err := Load(malformedFile); err == nil {
		t.Fatal("expected error loading malformed JSON, got nil")
	}

	// Test unknown fields rejection
	unknownFieldJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "unknown_property": true,
  "profiles": { "none": { "type": "none" } },
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 500, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	unknownFile := filepath.Join(tempDir, "unknown.json")
	if err := os.WriteFile(unknownFile, []byte(unknownFieldJSON), 0600); err != nil {
		t.Fatalf("write unknown field temp config: %v", err)
	}
	if _, err := Load(unknownFile); err == nil {
		t.Fatal("expected error loading JSON with unknown field, got nil")
	}
}

func TestValidateDoHConfig(t *testing.T) {
	t.Run("enabled with empty endpoints", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DoH.Enabled = true
		cfg.DoH.Endpoints = []DoHEndpoint{}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for enabled DoH with empty endpoints")
		}
	})

	t.Run("invalid non-https scheme", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DoH.Endpoints = []DoHEndpoint{
			{URL: "http://cloudflare-dns.com/dns-query", BootstrapIPs: []string{"1.1.1.1"}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for http URL in DoH endpoint")
		}
	})

	t.Run("hostname endpoint without bootstrap IPs", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DoH.Endpoints = []DoHEndpoint{
			{URL: "https://cloudflare-dns.com/dns-query", BootstrapIPs: []string{}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for hostname endpoint lacking bootstrap IPs")
		}
	})

	t.Run("invalid bootstrap IP format", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DoH.Endpoints = []DoHEndpoint{
			{URL: "https://cloudflare-dns.com/dns-query", BootstrapIPs: []string{"invalid.ip.address"}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid bootstrap IP")
		}
	})

	t.Run("ip literal endpoint allowed without bootstrap IPs", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DoH.Endpoints = []DoHEndpoint{
			{URL: "https://1.1.1.1/dns-query", BootstrapIPs: nil},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config for IP literal endpoint, got %v", err)
		}
	})
}

func TestValidateDomainRulesConfig(t *testing.T) {
	t.Run("valid domain rules", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["split"] = ProfileConfig{Type: "tcp-write-split", Offset: "sni-mid"}
		cfg.DomainRules = []DomainRuleConfig{
			{Match: "example.com", Profile: "none"},
			{Match: "*.example.org", Profile: "split"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("undefined profile referenced in domain rule", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DomainRules = []DomainRuleConfig{
			{Match: "example.com", Profile: "non-existent-profile"},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for undefined profile in domain rule, got nil")
		}
	})

	t.Run("invalid pattern in domain rule", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DomainRules = []DomainRuleConfig{
			{Match: "*", Profile: "none"},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid domain rule pattern, got nil")
		}
	})

	t.Run("duplicate domain rules", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DomainRules = []DomainRuleConfig{
			{Match: "example.com", Profile: "none"},
			{Match: "EXAMPLE.COM.", Profile: "none"},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for duplicate domain rules, got nil")
		}
	})
}

func TestValidateIndependentCompositeOffsets(t *testing.T) {
	t.Run("valid independent string offsets", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "sni-start",
			WriteOffset:  "sni-end",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("valid case-insensitive and whitespace-trimmed offsets", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "  SNI-START  ",
			WriteOffset:  "  SNI-END  ",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config with case-insensitive/trimmed offsets, got: %v", err)
		}
	})

	t.Run("valid independent numeric offsets", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "20",
			WriteOffset:  "40",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("valid coexistence of legacy and independent offsets", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			Offset:       "sni-mid",
			RecordOffset: "sni-start",
			WriteOffset:  "sni-end",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("valid only record_offset specified", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			Offset:       "sni-mid",
			RecordOffset: "sni-start",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("valid only write_offset specified", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:        "tls-record-then-write-split",
			Offset:      "sni-mid",
			WriteOffset: "sni-end",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
	})

	t.Run("invalid negative record_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "-1",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative record_offset")
		}
	})

	t.Run("invalid zero record_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "0",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for zero record_offset")
		}
	})

	t.Run("invalid string record_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "invalid-offset",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid record_offset string")
		}
	})

	t.Run("invalid negative write_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:        "tls-record-then-write-split",
			WriteOffset: "-5",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative write_offset")
		}
	})

	t.Run("invalid zero write_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:        "tls-record-then-write-split",
			WriteOffset: "0",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for zero write_offset")
		}
	})

	t.Run("invalid string write_offset", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["comp"] = ProfileConfig{
			Type:        "tls-record-then-write-split",
			WriteOffset: "bad-offset",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid write_offset string")
		}
	})

	t.Run("record_offset on unsupported profile type", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["bad"] = ProfileConfig{
			Type:         "tcp-write-split",
			RecordOffset: "sni-start",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when record_offset is configured on non-composite profile")
		}
	})

	t.Run("write_offset on unsupported profile type", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profiles["bad"] = ProfileConfig{
			Type:        "none",
			WriteOffset: "sni-start",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when write_offset is configured on non-composite profile")
		}
	})

	t.Run("load JSON config with independent offsets", func(t *testing.T) {
		tempDir := t.TempDir()
		jsonContent := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "doh": {
    "enabled": false,
    "fallback_system": true,
    "endpoints": []
  },
  "profiles": {
    "none": { "type": "none" },
    "composite-indep": {
      "type": "tls-record-then-write-split",
      "record_offset": "sni-start",
      "write_offset": "sni-end",
      "delay_ms": 50
    }
  },
  "domain_rules": [],
  "timeouts": {
    "dial_ms": 5000,
    "initial_inspection_ms": 1000,
    "idle_s": 60
  },
  "limits": {
    "max_connections": 500,
    "max_initial_bytes": 65536
  },
  "log_level": "info"
}`
		configFile := filepath.Join(tempDir, "config_composite.json")
		if err := os.WriteFile(configFile, []byte(jsonContent), 0600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		loaded, err := Load(configFile)
		if err != nil {
			t.Fatalf("Load returned unexpected error: %v", err)
		}
		prof := loaded.Profiles["composite-indep"]
		if prof.RecordOffset != "sni-start" {
			t.Errorf("expected RecordOffset 'sni-start', got %q", prof.RecordOffset)
		}
		if prof.WriteOffset != "sni-end" {
			t.Errorf("expected WriteOffset 'sni-end', got %q", prof.WriteOffset)
		}
		if prof.DelayMS != 50 {
			t.Errorf("expected DelayMS 50, got %d", prof.DelayMS)
		}
	})
}

func TestValidatePhase2Mode(t *testing.T) {
	t.Run("default mode is proxy", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Mode != ModeProxy {
			t.Fatalf("expected default mode %q, got %q", ModeProxy, cfg.Mode)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("empty mode normalizes to proxy", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = ""
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if cfg.Mode != ModeProxy {
			t.Fatalf("expected empty mode to normalize to %q, got %q", ModeProxy, cfg.Mode)
		}
	})

	t.Run("valid packet mode case-insensitivity", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = "PACKET"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if cfg.Mode != ModePacket {
			t.Fatalf("expected mode to normalize to %q, got %q", ModePacket, cfg.Mode)
		}
	})

	t.Run("invalid mode rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = "kernel-driver"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid mode")
		}
	})
}

func TestValidatePhase2PacketConfig(t *testing.T) {
	t.Run("valid default packet config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Mode = ModePacket
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error for default packet config: %v", err)
		}
		if !cfg.Packet.DropQUICOrDefault() {
			t.Fatal("expected DropQUICOrDefault to be true")
		}
	})

	t.Run("valid fake modes", func(t *testing.T) {
		validModes := []string{
			"none", "ttl", "multi-ttl", "ttl-auto", "wrong-chksum", "bad-chksum", "both",
			"ttl+wrong-chksum", "ttl, bad-checksum", "ttl | wrong-chksum",
			"multi-ttl+wrong-chksum",
		}
		for _, m := range validModes {
			cfg := DefaultConfig()
			cfg.Packet.FakePacketMode = m
			if err := cfg.Validate(); err != nil {
				t.Errorf("mode %q failed validation: %v", m, err)
			}
		}
		if defTTL := DefaultConfig().Packet.FakeTTL; defTTL != 4 {
			t.Errorf("expected DefaultConfig().Packet.FakeTTL == 4, got %d", defTTL)
		}
	})

	t.Run("invalid fake mode", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Packet.FakePacketMode = "unsupported-magic"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for unsupported fake packet mode")
		}
	})

	t.Run("valid fake TTL bounds", func(t *testing.T) {
		for _, ttl := range []int{2, 5, 16} {
			cfg := DefaultConfig()
			cfg.Packet.FakeTTL = ttl
			if err := cfg.Validate(); err != nil {
				t.Errorf("ttl %d failed validation: %v", ttl, err)
			}
		}
	})

	t.Run("invalid fake TTL bounds", func(t *testing.T) {
		for _, ttl := range []int{-1, 1, 17, 64} {
			cfg := DefaultConfig()
			cfg.Packet.FakeTTL = ttl
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected error for out-of-bounds fake TTL %d", ttl)
			}
		}
	})

	t.Run("valid fake SNI", func(t *testing.T) {
		for _, sni := range []string{"www.example.com", "cloudflare.com", "discord.gg"} {
			cfg := DefaultConfig()
			cfg.Packet.FakeSNI = sni
			if err := cfg.Validate(); err != nil {
				t.Errorf("fake SNI %q failed validation: %v", sni, err)
			}
		}
	})

	t.Run("invalid fake SNI", func(t *testing.T) {
		for _, sni := range []string{"   ", "bad domain with spaces", "https://example.com", strings.Repeat("a", 254)} {
			cfg := DefaultConfig()
			cfg.Packet.FakeSNI = sni
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected error for invalid fake SNI %q", sni)
			}
		}
	})

	t.Run("fake delay bounds", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Packet.FakeDelayMS = -1
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative fake_delay_ms")
		}
		cfg.Packet.FakeDelayMS = 10001
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for excessive fake_delay_ms")
		}
		cfg.Packet.FakeDelayMS = 50
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("split offset validation", func(t *testing.T) {
		validOffsets := []string{"sni-start", "sni-mid", "sni-end", "5", "100"}
		for _, off := range validOffsets {
			cfg := DefaultConfig()
			cfg.Packet.SplitOffset = off
			if err := cfg.Validate(); err != nil {
				t.Errorf("valid split offset %q failed: %v", off, err)
			}
		}

		invalidOffsets := []string{"-1", "0", "bad-offset"}
		for _, off := range invalidOffsets {
			cfg := DefaultConfig()
			cfg.Packet.SplitOffset = off
			if err := cfg.Validate(); err == nil {
				t.Errorf("expected error for invalid split offset %q", off)
			}
		}
	})

	t.Run("inter-packet delay bounds", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Packet.InterPacketDelayMS = -5
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative inter_packet_delay_ms")
		}
		cfg.Packet.InterPacketDelayMS = 20000
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for excessive inter_packet_delay_ms")
		}
		cfg.Packet.InterPacketDelayMS = 10
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("drop quic toggle", func(t *testing.T) {
		cfg := DefaultConfig()
		dropFalse := false
		cfg.Packet.DropQUIC = &dropFalse
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Packet.DropQUICOrDefault() {
			t.Fatal("expected DropQUICOrDefault to be false")
		}
	})

	t.Run("intercept dns toggle", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Packet.InterceptDNSOrDefault() {
			t.Fatal("expected default InterceptDNSOrDefault to be false")
		}
		dnsTrue := true
		cfg.Packet.InterceptDNS = &dnsTrue
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Packet.InterceptDNSOrDefault() {
			t.Fatal("expected InterceptDNSOrDefault to be true")
		}
	})
}

func TestBackwardCompatibility_Phase1JSON(t *testing.T) {
	tempDir := t.TempDir()
	phase1JSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "doh": {
    "enabled": false,
    "fallback_system": true,
    "endpoints": []
  },
  "profiles": {
    "none": { "type": "none" },
    "write-split": {
      "type": "tcp-write-split",
      "offset": "sni-mid",
      "delay_ms": 0
    }
  },
  "domain_rules": [
    { "match": "example.com", "profile": "write-split" }
  ],
  "timeouts": {
    "dial_ms": 8000,
    "initial_inspection_ms": 1000,
    "idle_s": 120
  },
  "limits": {
    "max_connections": 1000,
    "max_initial_bytes": 65536
  },
  "log_level": "info"
}`
	configFile := filepath.Join(tempDir, "config_phase1.json")
	if err := os.WriteFile(configFile, []byte(phase1JSON), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	loaded, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load returned unexpected error for Phase 1 JSON: %v", err)
	}
	if loaded.Mode != ModeProxy {
		t.Fatalf("expected Mode %q, got %q", ModeProxy, loaded.Mode)
	}
	if !loaded.Packet.DropQUICOrDefault() {
		t.Fatal("expected DropQUICOrDefault to default to true for omitted packet section")
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("Phase 1 config failed Validate(): %v", err)
	}
}

func TestPhase2JSONLoading(t *testing.T) {
	tempDir := t.TempDir()
	phase2JSON := `{
  "version": 1,
  "mode": "packet",
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "doh": {
    "enabled": false,
    "fallback_system": true,
    "endpoints": []
  },
  "profiles": {
    "none": { "type": "none" }
  },
  "domain_rules": [],
  "timeouts": {
    "dial_ms": 8000,
    "initial_inspection_ms": 1000,
    "idle_s": 120
  },
  "limits": {
    "max_connections": 1000,
    "max_initial_bytes": 65536
  },
  "log_level": "debug",
  "packet": {
    "fake_mode": "ttl+wrong-chksum",
    "fake_ttl": 4,
    "fake_sni": "safe.example.com",
    "fake_delay_ms": 5,
    "split_offset": "sni-start",
    "inter_packet_delay_ms": 2,
    "drop_quic": true,
    "intercept_dns": true
  }
}`
	configFile := filepath.Join(tempDir, "config_phase2.json")
	if err := os.WriteFile(configFile, []byte(phase2JSON), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	loaded, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load returned unexpected error for Phase 2 JSON: %v", err)
	}
	if loaded.Mode != ModePacket {
		t.Fatalf("expected Mode %q, got %q", ModePacket, loaded.Mode)
	}
	if loaded.Packet.FakePacketMode != "ttl+wrong-chksum" {
		t.Errorf("expected FakePacketMode 'ttl+wrong-chksum', got %q", loaded.Packet.FakePacketMode)
	}
	if loaded.Packet.FakeTTL != 4 {
		t.Errorf("expected FakeTTL 4, got %d", loaded.Packet.FakeTTL)
	}
	if loaded.Packet.FakeSNI != "safe.example.com" {
		t.Errorf("expected FakeSNI 'safe.example.com', got %q", loaded.Packet.FakeSNI)
	}
	if loaded.Packet.FakeDelayMS != 5 {
		t.Errorf("expected FakeDelayMS 5, got %d", loaded.Packet.FakeDelayMS)
	}
	if loaded.Packet.SplitOffset != "sni-start" {
		t.Errorf("expected SplitOffset 'sni-start', got %q", loaded.Packet.SplitOffset)
	}
	if loaded.Packet.InterPacketDelayMS != 2 {
		t.Errorf("expected InterPacketDelayMS 2, got %d", loaded.Packet.InterPacketDelayMS)
	}
	if !loaded.Packet.DropQUICOrDefault() {
		t.Errorf("expected DropQUICOrDefault true, got false")
	}
	if !loaded.Packet.InterceptDNSOrDefault() {
		t.Errorf("expected InterceptDNSOrDefault true, got false")
	}
}

func TestPacketConfig_InterceptDNS(t *testing.T) {
	t.Run("default empty PacketConfig returns false", func(t *testing.T) {
		var p PacketConfig
		if p.InterceptDNSOrDefault() {
			t.Error("expected InterceptDNSOrDefault to be false when nil")
		}
	})

	t.Run("DefaultConfig returns false", func(t *testing.T) {
		cfg := DefaultConfig()
		if cfg.Packet.InterceptDNSOrDefault() {
			t.Error("expected DefaultConfig InterceptDNSOrDefault to be false")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		bTrue := true
		p := PacketConfig{InterceptDNS: &bTrue}
		if !p.InterceptDNSOrDefault() {
			t.Error("expected InterceptDNSOrDefault to be true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		bFalse := false
		p := PacketConfig{InterceptDNS: &bFalse}
		if p.InterceptDNSOrDefault() {
			t.Error("expected InterceptDNSOrDefault to be false")
		}
	})
}

func TestPacketConfig_AutoLearn(t *testing.T) {
	t.Run("default empty PacketConfig returns true", func(t *testing.T) {
		var p PacketConfig
		if !p.AutoLearnOrDefault() {
			t.Error("expected AutoLearnOrDefault to be true when nil")
		}
	})

	t.Run("DefaultConfig returns true", func(t *testing.T) {
		cfg := DefaultConfig()
		if !cfg.Packet.AutoLearnOrDefault() {
			t.Error("expected DefaultConfig AutoLearnOrDefault to be true")
		}
		if cfg.Packet.AutoLearnPath != "autolearn.json" {
			t.Errorf("expected AutoLearnPath 'autolearn.json', got %q", cfg.Packet.AutoLearnPath)
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		bTrue := true
		p := PacketConfig{AutoLearn: &bTrue}
		if !p.AutoLearnOrDefault() {
			t.Error("expected AutoLearnOrDefault to be true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		bFalse := false
		p := PacketConfig{AutoLearn: &bFalse}
		if p.AutoLearnOrDefault() {
			t.Error("expected AutoLearnOrDefault to be false")
		}
	})
}

func TestRootConfigFilesValid(t *testing.T) {
	for _, filename := range []string{"../../config.json", "../../examples/config.phase2-test.json", "../../config.phase2-test.json", "../../config.sample.json"} {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			continue
		}
		cfg, err := Load(filename)
		if err != nil {
			t.Fatalf("Load(%q) failed: %v", filename, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%q) failed: %v", filename, err)
		}

		if strings.Contains(filename, "config.json") || strings.Contains(filename, "config.phase2-test.json") {
			if !cfg.Packet.InterceptDNSOrDefault() {
				t.Errorf("%s: expected InterceptDNSOrDefault to be true", filename)
			}
			if !cfg.DoH.Enabled {
				t.Errorf("%s: expected DoH.Enabled to be true", filename)
			}
			if len(cfg.DoH.Endpoints) < 2 {
				t.Errorf("%s: expected at least 2 DoH endpoints (Cloudflare and Google), got %d", filename, len(cfg.DoH.Endpoints))
			}
			if len(cfg.HostsSync.DomainsOrDefault()) == 0 {
				t.Errorf("%s: expected non-empty hosts_sync domains", filename)
			}
		}
	}
}

func TestHostsSyncConfigValidation(t *testing.T) {
	t.Run("default domains non-empty", func(t *testing.T) {
		cfg := DefaultConfig()
		domains := cfg.HostsSync.DomainsOrDefault()
		if len(domains) == 0 {
			t.Fatal("expected default hosts_sync domains to be non-empty")
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("DefaultConfig validation failed: %v", err)
		}
	})

	t.Run("custom valid domains pass", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"custom.domain.org", "api.service.io"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid custom domains to pass, got: %v", err)
		}
	})

	t.Run("wildcard domain rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"*.discord.com"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for wildcard in hosts_sync.domains, got nil")
		}
		if !strings.Contains(err.Error(), "wildcards are not supported") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("whitespace in domain rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"invalid domain.com"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for whitespace in domain, got nil")
		}
	})

	t.Run("empty string domain rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{""}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for empty domain string, got nil")
		}
	})

	t.Run("IP address rejected in hosts_sync domains", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"192.168.1.1"}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for IP address in hosts_sync.domains, got nil")
		}
		if !strings.Contains(err.Error(), "is an IP address") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("leading and trailing dots rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{".discord.com"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "leading or trailing dot") {
			t.Fatalf("expected leading dot error, got: %v", err)
		}

		cfg.HostsSync.Domains = []string{"discord.com."}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "leading or trailing dot") {
			t.Fatalf("expected trailing dot error, got: %v", err)
		}
	})

	t.Run("consecutive dots rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"discord..com"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "empty label") {
			t.Fatalf("expected consecutive dots error, got: %v", err)
		}
	})

	t.Run("leading and trailing hyphens rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.HostsSync.Domains = []string{"-discord.com"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "leading or trailing hyphen") {
			t.Fatalf("expected leading hyphen error, got: %v", err)
		}

		cfg.HostsSync.Domains = []string{"discord-.com"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "leading or trailing hyphen") {
			t.Fatalf("expected trailing hyphen error, got: %v", err)
		}
	})

	t.Run("label exceeding 63 chars rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		longLabel := strings.Repeat("a", 64)
		cfg.HostsSync.Domains = []string{longLabel + ".com"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds 63 characters") {
			t.Fatalf("expected label length error, got: %v", err)
		}
	})
}

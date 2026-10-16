package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/divert"
)

func TestCLIVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("unexpected error for version: %v", err)
	}
	if err := run([]string{"--version"}); err != nil {
		t.Fatalf("unexpected error for --version: %v", err)
	}
}

func TestCLIHelp(t *testing.T) {
	if err := run([]string{"help"}); err != nil {
		t.Fatalf("unexpected error for help: %v", err)
	}
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("unexpected error for --help: %v", err)
	}
}

func TestCLINoArgs(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("expected error when no args provided, got nil")
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown-cmd"}); err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
}

func TestCLIConfigValidateDefault(t *testing.T) {
	if err := run([]string{"config", "validate"}); err != nil {
		t.Fatalf("unexpected error validating default config: %v", err)
	}
}

func TestCLIConfigValidateFile(t *testing.T) {
	tempDir := t.TempDir()
	validJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "doh": { "enabled": false, "fallback_system": true, "endpoints": [] },
  "profiles": { "none": { "type": "none" } },
  "domain_rules": [],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 1000, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	validFile := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(validFile, []byte(validJSON), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if err := run([]string{"config", "validate", "--config", validFile}); err != nil {
		t.Fatalf("unexpected error validating valid config file: %v", err)
	}

	// Test invalid config file (e.g. non-loopback listen address)
	invalidJSON := strings.Replace(validJSON, "127.0.0.1:1080", "0.0.0.0:1080", 1)
	invalidFile := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidFile, []byte(invalidJSON), 0600); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	if err := run([]string{"config", "validate", "--config", invalidFile}); err == nil {
		t.Fatal("expected error validating non-loopback config, got nil")
	}
}

func TestCLICheckValidation(t *testing.T) {
	// Missing --domain
	if err := run([]string{"check"}); err == nil {
		t.Fatal("expected error for check without --domain, got nil")
	}

	// Invalid domain
	if err := run([]string{"check", "--domain", "*.wildcard.org"}); err == nil {
		t.Fatal("expected error for wildcard domain in check, got nil")
	}

	// Unknown profile referenced by domain rule must be rejected without network probe
	tempDir := t.TempDir()
	badConfigJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "profiles": { "none": { "type": "none" } },
  "domain_rules": [
    { "match": "bad.target.test", "profile": "non-existent-profile" }
  ],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 1000, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	badConfigFile := filepath.Join(tempDir, "bad_config.json")
	if err := os.WriteFile(badConfigFile, []byte(badConfigJSON), 0600); err != nil {
		t.Fatalf("failed to write bad config: %v", err)
	}

	err := run([]string{"check", "--domain", "bad.target.test", "--config", badConfigFile, "--port", "12345"})
	if err == nil {
		t.Fatal("expected error for check with unknown profile referenced in domain rule, got nil")
	}
	if !strings.Contains(err.Error(), "references undefined profile") && !strings.Contains(err.Error(), "does not exist in configuration") {
		t.Fatalf("expected undefined profile error, got: %v", err)
	}

	// Valid unmatched domain uses default profile (none)
	validConfigJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "profiles": { "none": { "type": "none" } },
  "domain_rules": [],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 1000, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	validConfigFile := filepath.Join(tempDir, "valid_config.json")
	if err := os.WriteFile(validConfigFile, []byte(validConfigJSON), 0600); err != nil {
		t.Fatalf("failed to write valid config: %v", err)
	}

	// Point to closed port: should attempt probe and get TCP connection failure (proving it reached probe phase)
	err = run([]string{"check", "--domain", "127.0.0.1", "--config", validConfigFile, "--port", "1"})
	if err == nil {
		t.Fatal("expected connection failure on port 1, got nil")
	}
	if !strings.Contains(err.Error(), "TCP_CONNECT_FAILURE") && !strings.Contains(err.Error(), "check finished with outcome") {
		t.Fatalf("expected TCP connect failure outcome, got: %v", err)
	}
}

func TestCLITuneValidation(t *testing.T) {
	// Missing --domains
	if err := run([]string{"tune"}); err == nil {
		t.Fatal("expected error for tune without --domains, got nil")
	}

	// Invalid trials
	if err := run([]string{"tune", "--domains", "example.com", "--trials", "0"}); err == nil {
		t.Fatal("expected error for trials <= 0, got nil")
	}

	// Invalid delay
	if err := run([]string{"tune", "--domains", "example.com", "--delay-ms", "-1"}); err == nil {
		t.Fatal("expected error for negative delay-ms, got nil")
	}

	// Specified non-existent profile
	if err := run([]string{"tune", "--domains", "example.com", "--profiles", "non-existent-prof"}); err == nil {
		t.Fatal("expected error for undefined profile in tune, got nil")
	}

	// Apply without explicit --config
	if err := run([]string{"tune", "--domains", "example.com", "--apply"}); err == nil {
		t.Fatal("expected error for --apply on default config without --config, got nil")
	}
}

func TestCLISysproxyValidation(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentBackup := filepath.Join(tempDir, "missing_backup.json")

	// 1. Missing subcommand
	if err := run([]string{"sysproxy"}); err == nil {
		t.Fatal("expected error for sysproxy without subcommand, got nil")
	}

	// 2. Unknown subcommand
	if err := run([]string{"sysproxy", "unknown"}); err == nil {
		t.Fatal("expected error for unknown sysproxy subcommand, got nil")
	}

	// 3. Non-loopback address on 'on'
	err := run([]string{"sysproxy", "on", "--addr", "192.168.1.1:1080", "--backup", nonExistentBackup})
	if err == nil {
		t.Fatal("expected error for non-loopback address, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got: %v", err)
	}

	// 4. Unreachable listener on 'on' (valid loopback address, closed port)
	err = run([]string{"sysproxy", "on", "--addr", "127.0.0.1:1", "--backup", nonExistentBackup})
	if err == nil {
		t.Fatal("expected error for unreachable listener on port 1, got nil")
	}
	if !strings.Contains(err.Error(), "listener health check failed") && !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("expected listener health check error, got: %v", err)
	}

	// 5. 'off' with missing backup
	err = run([]string{"sysproxy", "off", "--backup", nonExistentBackup})
	if err == nil {
		t.Fatal("expected error for sysproxy off with missing backup, got nil")
	}
	if !strings.Contains(err.Error(), "missing or invalid recovery data") && !strings.Contains(err.Error(), "no backup file found") {
		t.Fatalf("expected missing backup error, got: %v", err)
	}

	// 6. 'restore' with missing backup
	err = run([]string{"sysproxy", "restore", "--backup", nonExistentBackup})
	if err == nil {
		t.Fatal("expected error for sysproxy restore with missing backup, got nil")
	}
	if !strings.Contains(err.Error(), "missing or invalid recovery data") && !strings.Contains(err.Error(), "no backup file found") {
		t.Fatalf("expected missing backup error, got: %v", err)
	}

	// 7. 'status' with missing backup should succeed and report state
	err = run([]string{"sysproxy", "status", "--backup", nonExistentBackup})
	if err != nil {
		t.Fatalf("unexpected error for sysproxy status with missing backup: %v", err)
	}
}

func TestCLISubcommandHelp(t *testing.T) {
	subcommands := [][]string{
		{"run", "--help"},
		{"run", "-h"},
		{"check", "--help"},
		{"check", "-h"},
		{"tune", "--help"},
		{"tune", "-h"},
		{"config", "--help"},
		{"config", "-h"},
		{"config", "validate", "--help"},
		{"config", "validate", "-h"},
		{"sysproxy", "--help"},
		{"sysproxy", "-h"},
		{"sysproxy", "on", "--help"},
		{"sysproxy", "on", "-h"},
		{"sysproxy", "off", "--help"},
		{"sysproxy", "off", "-h"},
		{"sysproxy", "status", "--help"},
		{"sysproxy", "status", "-h"},
		{"sysproxy", "restore", "--help"},
		{"sysproxy", "restore", "-h"},
		{"recover", "--help"},
		{"recover", "-h"},
	}

	for _, sc := range subcommands {
		t.Run(strings.Join(sc, " "), func(t *testing.T) {
			if err := run(sc); err != nil {
				t.Fatalf("subcommand %v failed with error: %v; expected clean exit (code 0)", sc, err)
			}
		})
	}
}

func TestCLIVersionFormat(t *testing.T) {
	// Test default version
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version error: %v", err)
	}

	// Test version with build metadata set
	oldCommit := commit
	oldBuildDate := buildDate
	defer func() {
		commit = oldCommit
		buildDate = oldBuildDate
	}()

	commit = "testcommit123"
	buildDate = "2026-10-12T00:00:00Z"
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version with metadata error: %v", err)
	}
}

func TestCLIRunPacketModeFlags(t *testing.T) {
	t.Run("invalid mode flag rejected", func(t *testing.T) {
		err := run([]string{"run", "--mode", "invalid-mode"})
		if err == nil {
			t.Fatal("expected error for invalid --mode flag, got nil")
		}
		if !strings.Contains(err.Error(), "invalid mode") {
			t.Fatalf("expected invalid mode error, got: %v", err)
		}
	})

	t.Run("invalid fake-ttl flag rejected", func(t *testing.T) {
		err := run([]string{"run", "--mode", "packet", "--fake-ttl", "25"})
		if err == nil {
			t.Fatal("expected error for invalid --fake-ttl, got nil")
		}
		if !strings.Contains(err.Error(), "packet.fake_ttl") {
			t.Fatalf("expected fake_ttl bounds error, got: %v", err)
		}
	})

	t.Run("invalid fake-mode flag rejected", func(t *testing.T) {
		err := run([]string{"run", "--mode", "packet", "--fake-mode", "bad-fake-strategy"})
		if err == nil {
			t.Fatal("expected error for invalid --fake-mode, got nil")
		}
		if !strings.Contains(err.Error(), "packet.fake_mode") {
			t.Fatalf("expected fake_mode validation error, got: %v", err)
		}
	})

	t.Run("invalid split-offset flag rejected", func(t *testing.T) {
		err := run([]string{"run", "--mode", "packet", "--split-offset", "bad-offset"})
		if err == nil {
			t.Fatal("expected error for invalid --split-offset, got nil")
		}
		if !strings.Contains(err.Error(), "split_offset") {
			t.Fatalf("expected split_offset error, got: %v", err)
		}
	})

	t.Run("packet mode un-elevated execution rejected safely", func(t *testing.T) {
		// When tests run without Administrator privileges, packet mode must exit with a clear error
		err := run([]string{"run", "--mode", "packet", "--fake-mode", "ttl", "--fake-ttl", "4"})
		if err == nil {
			t.Fatal("expected packet mode to fail in un-elevated test environment, got nil")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "administrative privileges required") && !strings.Contains(errStr, "WinDivert.dll not found") {
			t.Fatalf("expected elevation or DLL error, got: %v", err)
		}
	})

	t.Run("packet mode with intercept-dns flag rejected safely when unelevated", func(t *testing.T) {
		err := run([]string{"run", "--mode", "packet", "--intercept-dns"})
		if err == nil {
			t.Fatal("expected packet mode to fail in un-elevated test environment, got nil")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "administrative privileges required") && !strings.Contains(errStr, "WinDivert.dll not found") {
			t.Fatalf("expected elevation or DLL error, got: %v", err)
		}
	})

	t.Run("stop-file triggers graceful engine shutdown", func(t *testing.T) {
		stopFile := filepath.Join(t.TempDir(), "stop.signal")
		errCh := make(chan error, 1)
		go func() {
			errCh <- run([]string{"run", "--mode", "proxy", "--stop-file", stopFile, "--duration-s", "10"})
		}()

		time.Sleep(200 * time.Millisecond)
		if err := os.WriteFile(stopFile, []byte("stop"), 0644); err != nil {
			t.Fatalf("failed to write stop file: %v", err)
		}

		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("expected clean exit from stop file, got: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("engine did not shut down within 3s after stop file was created")
		}
	})
}

func TestCLIRecoverCommand(t *testing.T) {
	t.Run("recover --check-only succeeds", func(t *testing.T) {
		if err := run([]string{"recover", "--check-only"}); err != nil {
			t.Fatalf("recover --check-only failed: %v", err)
		}
	})

	t.Run("recover --status succeeds", func(t *testing.T) {
		if err := run([]string{"recover", "--status"}); err != nil {
			t.Fatalf("recover --status failed: %v", err)
		}
	})

	t.Run("recover default succeeds", func(t *testing.T) {
		if err := run([]string{"recover"}); err != nil {
			t.Fatalf("recover execution failed: %v", err)
		}
	})

	t.Run("recover with custom non-existent backup succeeds without crashing", func(t *testing.T) {
		nonExistent := filepath.Join(t.TempDir(), "missing_backup.json")
		if err := run([]string{"recover", "--backup", nonExistent, "--status"}); err != nil {
			t.Fatalf("recover with non-existent backup failed: %v", err)
		}
	})
}

func TestScriptsAre7BitASCII(t *testing.T) {
	root := filepath.Join("..", "..")
	scripts := []string{
		"build.ps1",
		"test-live.ps1",
		"start-bypass.bat",
		"stop-and-recover.bat",
		"launch-discord.bat",
	}

	for _, s := range scripts {
		p := filepath.Join(root, s)
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", s, err)
		}
		for i, b := range data {
			if b > 127 {
				t.Errorf("%s contains non-ASCII byte 0x%02X at offset %d", s, b, i)
				break
			}
		}
	}
}

func TestHarnessConfig_DoHInitialization(t *testing.T) {
	root := filepath.Join("..", "..")

	testConfigs := []string{filepath.Join("examples", "config.phase2-test.json"), "config.json"}
	for _, cfgName := range testConfigs {
		cfgPath := filepath.Join(root, cfgName)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("failed to load %s: %v", cfgName, err)
		}

		if cfg.Packet.FakePacketMode != "ttl" {
			t.Fatalf("%s: expected fake_mode == 'ttl', got %q", cfgName, cfg.Packet.FakePacketMode)
		}
		if cfg.Packet.FakeTTL != 4 {
			t.Fatalf("%s: expected fake_ttl == 4, got %d", cfgName, cfg.Packet.FakeTTL)
		}
		if cfg.DefaultProfile != "packet-default" {
			t.Fatalf("%s: expected default_profile == 'packet-default', got %q", cfgName, cfg.DefaultProfile)
		}
		if _, ok := cfg.Profiles["packet-default"]; !ok {
			t.Fatalf("%s: expected 'packet-default' in profiles map", cfgName)
		}

		harnessCfg, err := buildHarnessConfig(cfg, nil, false)
		if err != nil {
			t.Fatalf("%s: buildHarnessConfig returned error: %v", cfgName, err)
		}

		if !harnessCfg.InterceptDNS {
			t.Fatalf("%s: expected InterceptDNS to be true, got false", cfgName)
		}
		if harnessCfg.DoHResolver == nil {
			t.Fatalf("%s: expected non-nil DoHResolver", cfgName)
		}
		if harnessCfg.DNSResolver == nil {
			t.Fatalf("%s: expected non-nil DNSResolver", cfgName)
		}
		if harnessCfg.Filter != divert.FilterOutboundWithDNS {
			t.Fatalf("%s: expected filter to be FilterOutboundWithDNS (%q), got %q", cfgName, divert.FilterOutboundWithDNS, harnessCfg.Filter)
		}
	}

	t.Run("doh disabled in config but InterceptDNS enabled forces resolver initialization", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.DoH.Enabled = false
		cfg.DoH.Endpoints = nil
		interceptTrue := true
		cfg.Packet.InterceptDNS = &interceptTrue

		hCfg, err := buildHarnessConfig(cfg, nil, false)
		if err != nil {
			t.Fatalf("buildHarnessConfig error: %v", err)
		}
		if !hCfg.InterceptDNS {
			t.Fatal("expected InterceptDNS to be true")
		}
		if hCfg.DoHResolver == nil {
			t.Fatal("expected non-nil DoHResolver even when DoH was initially disabled")
		}
		if hCfg.DNSResolver == nil {
			t.Fatal("expected non-nil DNSResolver even when DoH was initially disabled")
		}
		if len(hCfg.DoHEndpoints) == 0 {
			t.Fatal("expected default DoH bootstrap endpoints to be populated")
		}
	})

	t.Run("InterceptDNS false leaves resolvers nil and filter production", func(t *testing.T) {
		cfg := config.DefaultConfig()
		interceptFalse := false
		cfg.Packet.InterceptDNS = &interceptFalse

		hCfg, err := buildHarnessConfig(cfg, nil, false)
		if err != nil {
			t.Fatalf("buildHarnessConfig error: %v", err)
		}
		if hCfg.InterceptDNS {
			t.Fatal("expected InterceptDNS to be false")
		}
		if hCfg.DoHResolver != nil || hCfg.DNSResolver != nil {
			t.Fatal("expected nil resolvers when InterceptDNS is false")
		}
		if hCfg.Filter != divert.FilterOutboundProduction {
			t.Fatalf("expected FilterOutboundProduction (%q), got %q", divert.FilterOutboundProduction, hCfg.Filter)
		}
	})
}

package tuner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dpibypass/internal/config"
)

func TestApplyRefusals(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")

	initialJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "profiles": {
    "none": { "type": "none" },
    "write-split": { "type": "tcp-write-split", "offset": "sni-mid" }
  },
  "domain_rules": [],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 500, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// 1. Refuse when recommendation is baseline "none"
	baselineOkResults := []DomainTuneResult{
		{
			Domain:               "example.com",
			RecommendedProfile:   "none",
			RecommendationReason: "Baseline works",
			IsConclusive:         true,
		},
	}
	if _, err := SafeApplyRecommendation(cfgPath, baselineOkResults); err == nil {
		t.Fatal("expected error when baseline works, got nil")
	}

	// 2. Refuse when recommendation is inconclusive
	inconclusiveResults := []DomainTuneResult{
		{
			Domain:               "example.com",
			RecommendedProfile:   "",
			RecommendationReason: "Inconclusive results",
			IsConclusive:         false,
		},
	}
	if _, err := SafeApplyRecommendation(cfgPath, inconclusiveResults); err == nil {
		t.Fatal("expected error when recommendation is inconclusive, got nil")
	}

	// 3. Refuse when .bak already exists
	bakPath := cfgPath + ".bak"
	if err := os.WriteFile(bakPath, []byte("pre-existing backup"), 0644); err != nil {
		t.Fatalf("write mock backup: %v", err)
	}

	conclusiveResults := []DomainTuneResult{
		{
			Domain:               "example.com",
			RecommendedProfile:   "write-split",
			RecommendationReason: "Repeatable improvement",
			IsConclusive:         true,
		},
	}
	if _, err := SafeApplyRecommendation(cfgPath, conclusiveResults); err == nil {
		t.Fatal("expected error when .bak already exists, got nil")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}

	// Verify original file remained unchanged
	content, err := os.ReadFile(cfgPath)
	if err != nil || string(content) != initialJSON {
		t.Fatal("original config was unexpectedly modified after refusal")
	}
}

func TestApplySuccessAndFieldPreservation(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")

	// Initial config contains an unknown custom property "custom_metadata" to verify preservation
	initialJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "custom_metadata": {
    "authored_by": "test-suite",
    "special_flag": 42
  },
  "profiles": {
    "none": { "type": "none" },
    "write-split": { "type": "tcp-write-split", "offset": "sni-mid" }
  },
  "domain_rules": [
    { "match": "old.example.com", "profile": "none" },
    { "match": "existing.target.com", "profile": "none" }
  ],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 500, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	results := []DomainTuneResult{
		{
			Domain:               "existing.target.com",
			RecommendedProfile:   "write-split",
			RecommendationReason: "Observed improvement",
			IsConclusive:         true,
		},
		{
			Domain:               "new.domain.org",
			RecommendedProfile:   "write-split",
			RecommendationReason: "Observed improvement",
			IsConclusive:         true,
		},
	}

	applyRes, err := SafeApplyRecommendation(cfgPath, results)
	if err != nil {
		t.Fatalf("SafeApplyRecommendation failed: %v", err)
	}

	if len(applyRes.Updated) != 1 || applyRes.Updated[0] != "existing.target.com" {
		t.Errorf("expected 1 updated domain 'existing.target.com', got: %v", applyRes.Updated)
	}
	if len(applyRes.Added) != 1 || applyRes.Added[0] != "new.domain.org" {
		t.Errorf("expected 1 added domain 'new.domain.org', got: %v", applyRes.Added)
	}

	// 1. Verify backup file exists and matches original exactly
	bakPath := cfgPath + ".bak"
	bakBytes, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(bakBytes) != initialJSON {
		t.Fatal("backup content does not match initial JSON")
	}

	// 2. Verify new file loads and validates cleanly
	newBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}

	// Verify custom metadata survived
	var genericMap map[string]any
	if err := json.Unmarshal(newBytes, &genericMap); err != nil {
		t.Fatalf("unmarshal generic updated config: %v", err)
	}
	customMeta, ok := genericMap["custom_metadata"].(map[string]any)
	if !ok || customMeta["authored_by"] != "test-suite" {
		t.Fatalf("custom_metadata was not preserved: %v", genericMap["custom_metadata"])
	}

	// Verify typed config validation succeeds
	parsedCfg := &config.Config{}
	if err := json.Unmarshal(newBytes, parsedCfg); err != nil {
		t.Fatalf("unmarshal into typed config: %v", err)
	}
	if err := parsedCfg.Validate(); err != nil {
		t.Fatalf("parsed config failed Validate(): %v", err)
	}

	// Check domain rules in parsed config
	matcher, err := config.NewDomainMatcher(parsedCfg.DomainRules)
	if err != nil {
		t.Fatalf("NewDomainMatcher failed on updated config: %v", err)
	}
	prof1, ok1 := matcher.Match("existing.target.com")
	if !ok1 || prof1 != "write-split" {
		t.Errorf("expected existing.target.com -> write-split, got %q (ok=%v)", prof1, ok1)
	}
	prof2, ok2 := matcher.Match("new.domain.org")
	if !ok2 || prof2 != "write-split" {
		t.Errorf("expected new.domain.org -> write-split, got %q (ok=%v)", prof2, ok2)
	}
	prof3, ok3 := matcher.Match("old.example.com")
	if !ok3 || prof3 != "none" {
		t.Errorf("expected old.example.com -> none, got %q (ok=%v)", prof3, ok3)
	}
}

func TestApplyRenameFailureWithIntactOriginal(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")

	initialJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "profiles": {
    "none": { "type": "none" },
    "write-split": { "type": "tcp-write-split", "offset": "sni-mid" }
  },
  "domain_rules": [],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 500, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Inject rename failure seam
	origRename := renameFile
	renameFile = func(oldpath, newpath string) error {
		return os.ErrPermission
	}
	defer func() { renameFile = origRename }()

	results := []DomainTuneResult{
		{
			Domain:               "fail.test.org",
			RecommendedProfile:   "write-split",
			RecommendationReason: "Conclusive improvement",
			IsConclusive:         true,
		},
	}

	_, err := SafeApplyRecommendation(cfgPath, results)
	if err == nil {
		t.Fatal("expected error on rename failure, got nil")
	}
	if !strings.Contains(err.Error(), "original configuration remains intact") {
		t.Fatalf("expected 'original configuration remains intact' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), cfgPath+".bak") {
		t.Fatalf("expected backup path in error, got: %v", err)
	}

	// Verify original file is genuinely intact
	readBack, err := os.ReadFile(cfgPath)
	if err != nil || string(readBack) != initialJSON {
		t.Fatal("original configuration file was corrupted after rename failure")
	}

	// Verify backup exists and matches original
	bakBytes, err := os.ReadFile(cfgPath + ".bak")
	if err != nil || string(bakBytes) != initialJSON {
		t.Fatal("backup file missing or mismatch after rename failure")
	}

	// Verify temporary files were cleaned up
	entries, _ := os.ReadDir(tempDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temporary file %q was not cleaned up after failure", e.Name())
		}
	}
}

func TestApplyRenameFailureWithRecoveryFailure(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")

	initialJSON := `{
  "version": 1,
  "listen": "127.0.0.1:1080",
  "default_profile": "none",
  "profiles": {
    "none": { "type": "none" },
    "write-split": { "type": "tcp-write-split", "offset": "sni-mid" }
  },
  "domain_rules": [],
  "timeouts": { "dial_ms": 5000, "initial_inspection_ms": 1000, "idle_s": 60 },
  "limits": { "max_connections": 500, "max_initial_bytes": 65536 },
  "log_level": "info"
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Inject rename failure where target file was altered, and recovery also fails
	origRename := renameFile
	origRecovery := writeRecoveryFile
	renameFile = func(oldpath, newpath string) error {
		// Simulate partial overwrite / alteration before failure
		_ = os.WriteFile(cfgPath, []byte("PARTIALLY_CORRUPTED"), 0644)
		return os.ErrPermission
	}
	writeRecoveryFile = func(name string, data []byte, perm os.FileMode) error {
		return errors.New("simulated recovery disk full")
	}
	defer func() {
		renameFile = origRename
		writeRecoveryFile = origRecovery
	}()

	results := []DomainTuneResult{
		{
			Domain:               "fail2.test.org",
			RecommendedProfile:   "write-split",
			RecommendationReason: "Conclusive improvement",
			IsConclusive:         true,
		},
	}

	_, err := SafeApplyRecommendation(cfgPath, results)
	if err == nil {
		t.Fatal("expected error on rename and recovery failure, got nil")
	}
	if !strings.Contains(err.Error(), "subsequent recovery from backup also failed") {
		t.Fatalf("expected 'subsequent recovery from backup also failed' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "simulated recovery disk full") {
		t.Fatalf("expected recovery error message in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), cfgPath+".bak") {
		t.Fatalf("expected backup path reference in error, got: %v", err)
	}

	// Verified backup MUST still be present and intact
	bakBytes, err := os.ReadFile(cfgPath + ".bak")
	if err != nil || string(bakBytes) != initialJSON {
		t.Fatal("verified backup missing or corrupted after recovery failure")
	}
}

package tuner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"dpibypass/internal/config"
)

// Package-internal hooks for deterministic test injection.
var (
	renameFile        = os.Rename
	writeRecoveryFile = os.WriteFile
)

// ApplyResult summarizes the changes applied to a configuration file.
type ApplyResult struct {
	ConfigPath string
	BackupPath string
	Updated    []string // domains updated
	Added      []string // domains added
}

// SafeApplyRecommendation modifies configPath to apply recommendations from results.
// It enforces all safety invariants:
//  1. Recommends at least one profile improvement over 'none'.
//  2. Refuses if results are inconclusive, baseline succeeded, or trials failed.
//  3. Refuses exclusively if fixed backup path (<configPath>.bak) already exists (no TOCTOU race).
//  4. Preserves unknown JSON fields and custom properties by parsing into generic maps.
//  5. Validates resulting configuration in-memory before writing to disk.
//  6. Performs atomic replacement via temporary file with verified rollback protection.
func SafeApplyRecommendation(configPath string, results []DomainTuneResult) (*ApplyResult, error) {
	if configPath == "" {
		return nil, errors.New("configuration path cannot be empty")
	}

	// Filter conclusive improvements over baseline
	recommendations := make(map[string]string) // normalized domain -> recommended profile
	for _, res := range results {
		if !res.IsConclusive {
			continue
		}
		if res.RecommendedProfile == "" || res.RecommendedProfile == "none" {
			// Baseline succeeded or no change recommended
			continue
		}
		recommendations[config.NormalizeDomain(res.Domain)] = res.RecommendedProfile
	}

	if len(recommendations) == 0 {
		return nil, errors.New("no conclusive strategy improvements over baseline; configuration will not be modified")
	}

	// 1. Read original configuration bytes before creating backup
	origBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read original configuration file: %w", err)
	}

	// 2. Exclusively create verified backup file (<configPath>.bak) to prevent TOCTOU races
	backupPath, err := CreateAtomicBackup(configPath)
	if err != nil {
		return nil, err
	}

	// 4. Generic JSON unmarshal to preserve all unknown / nested fields
	var rawMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(origBytes))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return nil, fmt.Errorf("decode configuration JSON for generic update: %w", err)
	}

	// 5. Update or add domain rules in rawMap
	var updatedDomains []string
	var addedDomains []string

	var rawRules []any
	if existingRules, ok := rawMap["domain_rules"].([]any); ok {
		rawRules = existingRules
	}

	for normDomain, profile := range recommendations {
		found := false
		for i, item := range rawRules {
			if ruleMap, ok := item.(map[string]any); ok {
				if matchVal, ok := ruleMap["match"].(string); ok {
					if config.NormalizeDomain(matchVal) == normDomain {
						ruleMap["profile"] = profile
						rawRules[i] = ruleMap
						updatedDomains = append(updatedDomains, normDomain)
						found = true
						break
					}
				}
			}
		}
		if !found {
			newRule := map[string]any{
				"match":   normDomain,
				"profile": profile,
			}
			rawRules = append(rawRules, newRule)
			addedDomains = append(addedDomains, normDomain)
		}
	}
	rawMap["domain_rules"] = rawRules

	// 6. Serialize proposed configuration
	newBytes, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal updated configuration JSON: %w", err)
	}
	newBytes = append(newBytes, '\n')

	// 7. Validate updated configuration in-memory using strict config.Validate()
	parsedCfg := &config.Config{}
	strictDec := json.NewDecoder(bytes.NewReader(newBytes))
	strictDec.DisallowUnknownFields()
	if err := strictDec.Decode(parsedCfg); err != nil {
		// If strict decode fails due to unknown fields in rawMap, fall back to non-strict decode + Validate()
		parsedCfg = &config.Config{}
		if fallbackErr := json.Unmarshal(newBytes, parsedCfg); fallbackErr != nil {
			return nil, fmt.Errorf("unmarshal proposed configuration: %w", fallbackErr)
		}
	}
	if err := parsedCfg.Validate(); err != nil {
		return nil, fmt.Errorf("proposed configuration failed validation: %w", err)
	}

	// 8. Atomic replacement via temporary file
	dir := filepath.Dir(configPath)
	tmpFile, err := os.CreateTemp(dir, "dpibypass_cfg_*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temporary configuration file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName) // clean up tmp if still present
	}()

	if _, err := tmpFile.Write(newBytes); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("write to temporary configuration file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("sync temporary configuration file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temporary configuration file: %w", err)
	}

	// 9. Atomic rename temporary file to target path with verified recovery
	if err := renameFile(tmpName, configPath); err != nil {
		// Check whether the original file remained intact
		currentBytes, readErr := os.ReadFile(configPath)
		if readErr == nil && bytes.Equal(currentBytes, origBytes) {
			return nil, fmt.Errorf("atomic replacement failed: %w (original configuration remains intact; verified backup preserved at %s)", err, backupPath)
		}

		// Attempt recovery from verified backup
		restoreErr := writeRecoveryFile(configPath, origBytes, 0644)
		if restoreErr != nil {
			return nil, fmt.Errorf("atomic replacement failed: %v; subsequent recovery from backup also failed: %v (verified backup available at %s)", err, restoreErr, backupPath)
		}
		return nil, fmt.Errorf("atomic replacement failed: %v (restored original configuration from verified backup at %s)", err, backupPath)
	}

	return &ApplyResult{
		ConfigPath: configPath,
		BackupPath: backupPath,
		Updated:    updatedDomains,
		Added:      addedDomains,
	}, nil
}

// CreateAtomicBackup exclusively creates a verified backup file (<configPath>.bak).
// It returns an error if the backup file already exists or if verification fails.
func CreateAtomicBackup(configPath string) (string, error) {
	origBytes, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read original configuration file: %w", err)
	}

	backupPath := configPath + ".bak"
	backupFile, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("backup file %q already exists; refusing to modify configuration to prevent overwriting existing backup. Please review or remove the existing backup file first", backupPath)
		}
		return "", fmt.Errorf("create exclusive backup file %q: %w", backupPath, err)
	}

	if _, err := backupFile.Write(origBytes); err != nil {
		_ = backupFile.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("write backup file %q: %w", backupPath, err)
	}
	if err := backupFile.Sync(); err != nil {
		_ = backupFile.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("sync backup file %q: %w", backupPath, err)
	}
	if err := backupFile.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("close backup file %q: %w", backupPath, err)
	}

	readBack, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(readBack, origBytes) {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("backup verification failed: backup content does not match original (backup removed)")
	}

	return backupPath, nil
}

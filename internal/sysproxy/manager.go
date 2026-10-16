package sysproxy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Tracked registry value names.
const (
	KeyProxyEnable   = "ProxyEnable"
	KeyProxyServer   = "ProxyServer"
	KeyAutoConfigURL = "AutoConfigURL"
	KeyProxyOverride = "ProxyOverride"
)

// DefaultBackupPath resolves the standard per-user backup location:
// %LOCALAPPDATA%\dpibypass\sysproxy_backup.json.
// It fails cleanly if %LOCALAPPDATA% cannot be resolved, never silently falling back.
func DefaultBackupPath() (string, error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		userProfile := os.Getenv("USERPROFILE")
		if userProfile != "" {
			localAppData = filepath.Join(userProfile, "AppData", "Local")
		}
	}
	if localAppData == "" {
		return "", errors.New("cannot determine %LOCALAPPDATA% directory; please specify --backup <path> explicitly")
	}
	return filepath.Join(localAppData, "dpibypass", "sysproxy_backup.json"), nil
}

// EncodeDWORD encodes a 32-bit unsigned integer into 4 little-endian bytes.
func EncodeDWORD(val uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return buf
}

// DecodeDWORD decodes 4 little-endian bytes into a 32-bit unsigned integer.
func DecodeDWORD(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("insufficient bytes for DWORD: got %d, expected 4", len(b))
	}
	return binary.LittleEndian.Uint32(b[:4]), nil
}

// EncodeString encodes a UTF-8 string into null-terminated UTF-16LE bytes.
func EncodeString(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	u16 = append(u16, 0) // Null terminator
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}

// DecodeString decodes null-terminated UTF-16LE bytes into a UTF-8 string.
func DecodeString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16)), nil
}

// ValidateEndpoint validates that the proxy address is a valid loopback host and port.
func ValidateEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("endpoint cannot be empty")
	}

	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format (expected host:port): %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%w: got %q", ErrInvalidPort, portStr)
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			return "", fmt.Errorf("%w: %q is not a loopback address", ErrNotLoopback, host)
		}
	} else {
		lowerHost := strings.ToLower(host)
		if lowerHost != "localhost" {
			return "", fmt.Errorf("%w: %q is not localhost or a loopback IP", ErrNotLoopback, host)
		}
	}

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// Manager coordinates safe Windows Internet Settings proxy management.
type Manager struct {
	Store    Store
	DialFunc func(network, addr string, timeout time.Duration) (net.Conn, error)
}

// NewManager creates a Manager with the specified Store.
func NewManager(store Store) *Manager {
	return &Manager{
		Store:    store,
		DialFunc: net.DialTimeout,
	}
}

// checkListenerReachable verifies that the local listener is reachable before modifying OS settings.
func (m *Manager) checkListenerReachable(addr string, timeout time.Duration) error {
	dial := m.DialFunc
	if dial == nil {
		dial = net.DialTimeout
	}
	conn, err := dial("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("%w at %s: %w", ErrUnreachableListener, addr, err)
	}
	_ = conn.Close()
	return nil
}

// Enable activates the Windows system proxy for HTTP and HTTPS traffic after exhaustive checks.
func (m *Manager) Enable(endpoint string, backupPath string) (*EnableResult, error) {
	validatedAddr, err := ValidateEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("validate endpoint: %w", err)
	}

	// 1. Verify that the intended local listener is reachable
	if err := m.checkListenerReachable(validatedAddr, 500*time.Millisecond); err != nil {
		return nil, fmt.Errorf("pre-activation listener health check failed: %w", err)
	}

	// 2. Resolve backup path
	if backupPath == "" {
		resolved, err := DefaultBackupPath()
		if err != nil {
			return nil, err
		}
		backupPath = resolved
	}

	// 3. Refuse activation if an active or unretired backup already exists
	if _, err := os.Stat(backupPath); err == nil {
		return nil, fmt.Errorf("%w at %q; run 'dpibypass sysproxy status' or 'dpibypass sysproxy off' first",
			ErrBackupAlreadyExists, backupPath)
	}

	// 4. Read current AutoConfigURL and refuse if active PAC script is present
	autoConfigVal, err := m.Store.ReadValue(KeyAutoConfigURL)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", KeyAutoConfigURL, err)
	}
	if autoConfigVal.Exists && len(autoConfigVal.Data) > 0 {
		decodedPAC, _ := DecodeString(autoConfigVal.Data)
		if strings.TrimSpace(decodedPAC) != "" {
			return nil, fmt.Errorf("%w: detected %q; automatic proxy setup (PAC script) takes precedence over static proxy settings. Disable automatic proxy setup in Windows Settings before enabling dpibypass sysproxy",
				ErrAutoConfigActive, decodedPAC)
		}
	}

	// 5. Read current tracked values
	origEnable, err := m.Store.ReadValue(KeyProxyEnable)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", KeyProxyEnable, err)
	}
	origServer, err := m.Store.ReadValue(KeyProxyServer)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", KeyProxyServer, err)
	}

	origMap := map[string]RegistryValue{
		KeyProxyEnable: origEnable,
		KeyProxyServer: origServer,
	}

	// 6. Define applied state (explicit HTTP/HTTPS mapping)
	proxyServerMapping := "http=" + validatedAddr + ";https=" + validatedAddr
	appliedMap := map[string]RegistryValue{
		KeyProxyEnable: {
			Exists: true,
			Type:   REG_DWORD,
			Data:   EncodeDWORD(1),
		},
		KeyProxyServer: {
			Exists: true,
			Type:   REG_SZ,
			Data:   EncodeString(proxyServerMapping),
		},
	}

	backup := &Backup{
		Version:          1,
		Timestamp:        time.Now().UTC(),
		PID:              os.Getpid(),
		ConfiguredServer: proxyServerMapping,
		Original:         origMap,
		Applied:          appliedMap,
	}

	// 7. Write and verify backup file atomically before modifying registry
	if err := m.writeAndVerifyBackup(backupPath, backup); err != nil {
		return nil, fmt.Errorf("create and verify backup: %w", err)
	}

	// 8. Write applied settings to registry with automated rollback on failure
	rollback := func(step string, cause error) error {
		rbErr := m.applyValues(origMap)
		if rbErr != nil {
			return fmt.Errorf("%s failed (%w); %w: %v", step, cause, ErrRollbackFailed, rbErr)
		}
		// Rollback succeeded; remove backup file
		_ = os.Remove(backupPath)
		return fmt.Errorf("%s failed: %w (original registry settings were safely rolled back)", step, cause)
	}

	// Write ProxyServer first
	if err := m.Store.WriteValue(KeyProxyServer, appliedMap[KeyProxyServer].Type, appliedMap[KeyProxyServer].Data); err != nil {
		_ = os.Remove(backupPath)
		return nil, fmt.Errorf("set %s: %w", KeyProxyServer, err)
	}

	// Write ProxyEnable second
	if err := m.Store.WriteValue(KeyProxyEnable, appliedMap[KeyProxyEnable].Type, appliedMap[KeyProxyEnable].Data); err != nil {
		return nil, rollback("set "+KeyProxyEnable, err)
	}

	// 9. Read-back verification: verify settings in registry match applied values
	readBackCurrent, err := m.readCurrentTracked()
	if err != nil {
		return nil, rollback("read-back verification", err)
	}
	if !EqualValues(readBackCurrent, appliedMap) {
		return nil, rollback("read-back verification (mismatch)", ErrRestorationMismatch)
	}

	// 10. Notify WinINet
	var notifyWarn string
	if err := m.Store.NotifyWinINet(); err != nil {
		notifyWarn = fmt.Sprintf("WinINet notification warning: %v (registry settings were applied successfully, but running applications may require restart or refresh)", err)
	}

	return &EnableResult{
		ConfiguredServer:    proxyServerMapping,
		BackupPath:          backupPath,
		NotificationWarning: notifyWarn,
	}, nil
}

// Disable restores original proxy settings and retires the backup.
func (m *Manager) Disable(backupPath string, force bool) (*RestoreResult, error) {
	return m.Restore(backupPath, force)
}

// Restore restores original settings from a valid backup with strict state machine invariants.
func (m *Manager) Restore(backupPath string, force bool) (*RestoreResult, error) {
	if backupPath == "" {
		resolved, err := DefaultBackupPath()
		if err != nil {
			return nil, err
		}
		backupPath = resolved
	}

	// 1. Read and validate backup file
	backup, err := m.readBackup(backupPath)
	if err != nil {
		// Mandatory refusal: missing or corrupt backup never alters registry, even with --force
		return nil, fmt.Errorf("restore aborted: %w", err)
	}

	// 2. Read current registry state
	currentVals, err := m.readCurrentTracked()
	if err != nil {
		return nil, fmt.Errorf("read current registry settings: %w", err)
	}

	// 3. Evaluate restoration state machine
	matchesOriginal := EqualValues(currentVals, backup.Original)
	matchesApplied := EqualValues(currentVals, backup.Applied)

	// Case A: Current state already equals original state exactly -> Idempotent completion
	if matchesOriginal {
		if err := os.Remove(backupPath); err != nil {
			return nil, fmt.Errorf("settings are already restored, but failed to retire backup %q: %w", backupPath, err)
		}
		return &RestoreResult{
			AlreadyRestored: true,
			Success:         true,
			BackupRetired:   true,
			BackupPath:      backupPath,
		}, nil
	}

	// Case B & C: Drift evaluation
	if !matchesApplied && !force {
		diffs := DiffValues(currentVals, backup.Applied)
		return nil, fmt.Errorf("%w: current settings differ from applied state: %s. Use --force to restore the original backup anyway",
			ErrExternalModification, strings.Join(diffs, "; "))
	}

	// Case B / Case D (with --force): Restore original state from valid backup
	if err := m.applyValues(backup.Original); err != nil {
		// Retain backup file on failure
		return nil, fmt.Errorf("failed to write original settings to registry: %w (backup retained at %q)", err, backupPath)
	}

	// 4. Verify read-back matches original state exactly
	verifiedCurrent, err := m.readCurrentTracked()
	if err != nil {
		return nil, fmt.Errorf("failed to read back registry for verification: %w (backup retained at %q)", err, backupPath)
	}
	if !EqualValues(verifiedCurrent, backup.Original) {
		return nil, fmt.Errorf("%w: registry values do not match original backup (backup retained at %q)", ErrRestorationMismatch, backupPath)
	}

	// 5. Notify WinINet
	var notifyWarn string
	if err := m.Store.NotifyWinINet(); err != nil {
		notifyWarn = fmt.Sprintf("WinINet notification warning: %v (registry restored, but running applications may require restart or refresh)", err)
	}

	// 6. Safely retire backup file only after verified restoration
	if err := os.Remove(backupPath); err != nil {
		return nil, fmt.Errorf("settings restored and verified, but failed to remove backup file %q: %w", backupPath, err)
	}

	return &RestoreResult{
		Success:             true,
		Forced:              !matchesApplied,
		BackupRetired:       true,
		BackupPath:          backupPath,
		NotificationWarning: notifyWarn,
	}, nil
}

// Status inspects and returns the diagnostic status of the Windows proxy settings.
func (m *Manager) Status(backupPath string, listenerAddr string) (*Status, error) {
	if backupPath == "" {
		if resolved, err := DefaultBackupPath(); err == nil {
			backupPath = resolved
		}
	}

	currentVals, err := m.readCurrentTracked()
	if err != nil {
		return nil, fmt.Errorf("read registry settings: %w", err)
	}

	var autoConfigURL string
	if acVal, err := m.Store.ReadValue(KeyAutoConfigURL); err == nil && acVal.Exists {
		autoConfigURL, _ = DecodeString(acVal.Data)
	}

	var proxyOverride string
	if poVal, err := m.Store.ReadValue(KeyProxyOverride); err == nil && poVal.Exists {
		proxyOverride, _ = DecodeString(poVal.Data)
	}

	// Listener reachability check
	listenerReachable := false
	if listenerAddr != "" {
		if valAddr, err := ValidateEndpoint(listenerAddr); err == nil {
			listenerReachable = (m.checkListenerReachable(valAddr, 250*time.Millisecond) == nil)
		}
	}

	st := &Status{
		CurrentSettings:    currentVals,
		AutoConfigURL:      autoConfigURL,
		ProxyOverride:      proxyOverride,
		BackupPath:         backupPath,
		ListenerReachable:  listenerReachable,
		ConfiguredListener: listenerAddr,
	}

	// Inspect backup file
	if _, err := os.Stat(backupPath); err != nil {
		st.State = StateInactiveClean
		return st, nil
	}

	backup, err := m.readBackup(backupPath)
	if err != nil {
		st.State = StateCorruptBackup
		return st, nil
	}
	st.Backup = backup

	matchesOriginal := EqualValues(currentVals, backup.Original)
	matchesApplied := EqualValues(currentVals, backup.Applied)

	if matchesApplied {
		st.State = StateActive
	} else if matchesOriginal {
		st.State = StateInactiveDirtyBackup
	} else {
		st.State = StateExternalModification
		st.DriftDetails = DiffValues(currentVals, backup.Applied)
	}

	return st, nil
}

func (m *Manager) readCurrentTracked() (map[string]RegistryValue, error) {
	enableVal, err := m.Store.ReadValue(KeyProxyEnable)
	if err != nil {
		return nil, err
	}
	serverVal, err := m.Store.ReadValue(KeyProxyServer)
	if err != nil {
		return nil, err
	}
	return map[string]RegistryValue{
		KeyProxyEnable: enableVal,
		KeyProxyServer: serverVal,
	}, nil
}

func (m *Manager) applyValues(values map[string]RegistryValue) error {
	for name, val := range values {
		if !val.Exists {
			if err := m.Store.DeleteValue(name); err != nil {
				return fmt.Errorf("delete %s: %w", name, err)
			}
		} else {
			if err := m.Store.WriteValue(name, val.Type, val.Data); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}
	}
	return nil
}

func (m *Manager) writeAndVerifyBackup(path string, b *Backup) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup directory %q: %w", dir, err)
	}

	tmpFile := filepath.Join(dir, fmt.Sprintf("tmp_%d_%s", os.Getpid(), filepath.Base(path)))
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write temp backup: %w", err)
	}

	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename temp backup: %w", err)
	}

	// Verify by re-reading
	readBack, err := m.readBackup(path)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("verify backup read: %w", err)
	}

	if readBack.Version != b.Version || !EqualValues(readBack.Original, b.Original) || !EqualValues(readBack.Applied, b.Applied) {
		_ = os.Remove(path)
		return errors.New("backup content verification failed after write")
	}

	return nil
}

func (m *Manager) readBackup(path string) (*Backup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w at %q", ErrNoBackupFound, path)
		}
		return nil, fmt.Errorf("read backup file: %w", err)
	}

	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptBackup, err)
	}

	if b.Version != 1 || b.Original == nil || b.Applied == nil {
		return nil, fmt.Errorf("%w: invalid schema or missing required fields", ErrCorruptBackup)
	}

	return &b, nil
}

// EqualValues compares two maps of RegistryValue byte-for-byte.
func EqualValues(a, b map[string]RegistryValue) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if va.Exists != vb.Exists || va.Type != vb.Type || !bytes.Equal(va.Data, vb.Data) {
			return false
		}
	}
	return true
}

// DiffValues provides human-readable explanations of differences between current and expected states.
func DiffValues(current, expected map[string]RegistryValue) []string {
	var diffs []string
	for k, exp := range expected {
		cur, ok := current[k]
		if !ok || !cur.Exists {
			if exp.Exists {
				diffs = append(diffs, fmt.Sprintf("%s was removed (expected type %d)", k, exp.Type))
			}
			continue
		}
		if !exp.Exists {
			diffs = append(diffs, fmt.Sprintf("%s was added (type %d)", k, cur.Type))
			continue
		}
		if cur.Type != exp.Type {
			diffs = append(diffs, fmt.Sprintf("%s type changed from %d to %d", k, exp.Type, cur.Type))
			continue
		}
		if !bytes.Equal(cur.Data, exp.Data) {
			if cur.Type == REG_DWORD {
				curVal, _ := DecodeDWORD(cur.Data)
				expVal, _ := DecodeDWORD(exp.Data)
				diffs = append(diffs, fmt.Sprintf("%s changed from %d to %d", k, expVal, curVal))
			} else if cur.Type == REG_SZ {
				curStr, _ := DecodeString(cur.Data)
				expStr, _ := DecodeString(exp.Data)
				diffs = append(diffs, fmt.Sprintf("%s changed from %q to %q", k, expStr, curStr))
			} else {
				diffs = append(diffs, fmt.Sprintf("%s raw data changed", k))
			}
		}
	}
	return diffs
}

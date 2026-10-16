package sysproxy

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockStore struct {
	mu            sync.Mutex
	values        map[string]RegistryValue
	notifyErr     error
	writeErrHook  func(name string) error
	deleteErrHook func(name string) error
	readErrHook   func(name string) error
}

func newMockStore() *mockStore {
	return &mockStore{
		values: make(map[string]RegistryValue),
	}
}

func (m *mockStore) ReadValue(name string) (RegistryValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErrHook != nil {
		if err := m.readErrHook(name); err != nil {
			return RegistryValue{}, err
		}
	}
	v, ok := m.values[name]
	if !ok {
		return RegistryValue{Exists: false}, nil
	}
	return v, nil
}

func (m *mockStore) WriteValue(name string, valType uint32, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErrHook != nil {
		if err := m.writeErrHook(name); err != nil {
			return err
		}
	}
	m.values[name] = RegistryValue{
		Exists: true,
		Type:   valType,
		Data:   append([]byte(nil), data...),
	}
	return nil
}

func (m *mockStore) DeleteValue(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErrHook != nil {
		if err := m.deleteErrHook(name); err != nil {
			return err
		}
	}
	delete(m.values, name)
	return nil
}

func (m *mockStore) NotifyWinINet() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.notifyErr
}

// fakeConn implements net.Conn for mock reachability tests.
type fakeConn struct{}

func (f *fakeConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (f *fakeConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func reachableDialer(network, addr string, timeout time.Duration) (net.Conn, error) {
	return &fakeConn{}, nil
}

func unreachableDialer(network, addr string, timeout time.Duration) (net.Conn, error) {
	return nil, errors.New("connection refused (listener not running)")
}

func TestManagerFullLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()

	// Initial pre-existing state: ProxyEnable=0, ProxyServer="old.proxy:8080"
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}
	store.values[KeyProxyServer] = RegistryValue{
		Exists: true,
		Type:   REG_SZ,
		Data:   EncodeString("old.proxy:8080"),
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	// 1. Enable
	res, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if res.ConfiguredServer != "http=127.0.0.1:1080;https=127.0.0.1:1080" {
		t.Fatalf("unexpected configured server: %q", res.ConfiguredServer)
	}

	// Verify store state after Enable
	valEnable, _ := store.ReadValue(KeyProxyEnable)
	valServer, _ := store.ReadValue(KeyProxyServer)
	dw, _ := DecodeDWORD(valEnable.Data)
	str, _ := DecodeString(valServer.Data)
	if dw != 1 {
		t.Fatalf("expected ProxyEnable=1, got %d", dw)
	}
	if str != "http=127.0.0.1:1080;https=127.0.0.1:1080" {
		t.Fatalf("expected ProxyServer mapped to listener, got %q", str)
	}

	// 2. Check status while active
	status, err := mgr.Status(backupPath, "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if status.State != StateActive {
		t.Fatalf("expected StateActive, got %s", status.State)
	}
	if !status.ListenerReachable {
		t.Fatal("expected ListenerReachable true")
	}

	// 3. Disable
	restoreRes, err := mgr.Disable(backupPath, false)
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if !restoreRes.Success || !restoreRes.BackupRetired {
		t.Fatalf("unexpected restore result: %+v", restoreRes)
	}

	// 4. Verify original settings restored byte-for-byte
	valEnableRestored, _ := store.ReadValue(KeyProxyEnable)
	valServerRestored, _ := store.ReadValue(KeyProxyServer)
	dwRestored, _ := DecodeDWORD(valEnableRestored.Data)
	strRestored, _ := DecodeString(valServerRestored.Data)
	if dwRestored != 0 {
		t.Fatalf("expected ProxyEnable restored to 0, got %d", dwRestored)
	}
	if strRestored != "old.proxy:8080" {
		t.Fatalf("expected ProxyServer restored to old.proxy:8080, got %q", strRestored)
	}

	// Backup file must be deleted
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatal("expected backup file to be retired, but it still exists")
	}

	// 5. Check status after disable
	statusAfter, err := mgr.Status(backupPath, "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if statusAfter.State != StateInactiveClean {
		t.Fatalf("expected StateInactiveClean, got %s", statusAfter.State)
	}
}

func TestManagerMissingValueRestoration(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()

	// Initial pre-existing state: ProxyServer DOES NOT EXIST (clean Windows install)
	// ProxyEnable is 0
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}
	// Note: ProxyServer is omitted entirely from store.values

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	// Enable
	if _, err := mgr.Enable("127.0.0.1:1080", backupPath); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Verify ProxyServer was created
	srv, _ := store.ReadValue(KeyProxyServer)
	if !srv.Exists {
		t.Fatal("expected ProxyServer to exist after Enable")
	}

	// Disable
	if _, err := mgr.Disable(backupPath, false); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	// Verify ProxyServer was DELETED (not left as an empty string)
	srvAfter, _ := store.ReadValue(KeyProxyServer)
	if srvAfter.Exists {
		t.Fatal("expected ProxyServer to be deleted on restoration, but it still exists")
	}
}

func TestManagerUnreachableListenerRefusal(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()

	mgr := NewManager(store)
	mgr.DialFunc = unreachableDialer // Listener not running

	_, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err == nil {
		t.Fatal("expected Enable to fail when listener is unreachable, got nil")
	}
	if !errors.Is(err, ErrUnreachableListener) {
		t.Fatalf("expected ErrUnreachableListener, got: %v", err)
	}

	// Verify zero changes to store
	if len(store.values) != 0 {
		t.Fatalf("expected zero registry modifications, got %d values", len(store.values))
	}
	// Verify zero backup file created
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatal("expected no backup file to be created on unreachable listener")
	}
}

func TestManagerNonLoopbackEndpointRejection(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	// Non-loopback IPs
	for _, badAddr := range []string{
		"192.168.1.1:1080",
		"10.0.0.1:8080",
		"8.8.8.8:1080",
		"example.com:1080",
		"127.0.0.1:70000", // invalid port
		"127.0.0.1:0",     // invalid port
		"",
	} {
		_, err := mgr.Enable(badAddr, backupPath)
		if err == nil {
			t.Fatalf("expected error for bad address %q, got nil", badAddr)
		}
	}
}

func TestManagerAutoConfigActiveRefusal(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.values[KeyAutoConfigURL] = RegistryValue{
		Exists: true,
		Type:   REG_SZ,
		Data:   EncodeString("http://wpad.corp.local/wpad.dat"),
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	_, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err == nil {
		t.Fatal("expected Enable to fail when AutoConfigURL is active, got nil")
	}
	if !errors.Is(err, ErrAutoConfigActive) {
		t.Fatalf("expected ErrAutoConfigActive, got: %v", err)
	}

	// Ensure settings and AutoConfigURL were completely untouched
	ac, _ := store.ReadValue(KeyAutoConfigURL)
	str, _ := DecodeString(ac.Data)
	if str != "http://wpad.corp.local/wpad.dat" {
		t.Fatalf("AutoConfigURL was modified unexpectedly: %q", str)
	}
	if _, ok := store.values[KeyProxyEnable]; ok {
		t.Fatal("ProxyEnable was set despite AutoConfigURL refusal")
	}
}

func TestManagerExistingBackupGuard(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	if err := os.WriteFile(backupPath, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	store := newMockStore()
	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	_, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err == nil {
		t.Fatal("expected Enable to fail when backup file exists, got nil")
	}
	if !errors.Is(err, ErrBackupAlreadyExists) {
		t.Fatalf("expected ErrBackupAlreadyExists, got: %v", err)
	}
}

func TestManagerDriftDetectionAndForce(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	// Enable
	if _, err := mgr.Enable("127.0.0.1:1080", backupPath); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// External app mutates ProxyServer
	store.WriteValue(KeyProxyServer, REG_SZ, EncodeString("vpn.corporate.internal:8080"))

	// Status must detect external modification
	st, err := mgr.Status(backupPath, "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if st.State != StateExternalModification {
		t.Fatalf("expected StateExternalModification, got %s", st.State)
	}
	if len(st.DriftDetails) == 0 {
		t.Fatal("expected DriftDetails to contain explanation")
	}

	// Attempt Restore without --force: MUST REFUSE
	_, err = mgr.Disable(backupPath, false)
	if err == nil {
		t.Fatal("expected Restore without --force to fail on drift, got nil")
	}
	if !errors.Is(err, ErrExternalModification) {
		t.Fatalf("expected ErrExternalModification, got: %v", err)
	}

	// Verify external settings were NOT touched
	currSrv, _ := store.ReadValue(KeyProxyServer)
	currStr, _ := DecodeString(currSrv.Data)
	if currStr != "vpn.corporate.internal:8080" {
		t.Fatalf("external settings were modified despite refusal: %q", currStr)
	}
	// Backup file must still be preserved
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal("backup file was lost after drift refusal")
	}

	// Attempt Restore WITH --force: MUST SUCCEED
	res, err := mgr.Disable(backupPath, true)
	if err != nil {
		t.Fatalf("forced Restore failed: %v", err)
	}
	if !res.Success || !res.Forced || !res.BackupRetired {
		t.Fatalf("unexpected forced restore result: %+v", res)
	}

	// Verify original settings restored (ProxyEnable=0, ProxyServer deleted)
	valEnable, _ := store.ReadValue(KeyProxyEnable)
	dw, _ := DecodeDWORD(valEnable.Data)
	if dw != 0 {
		t.Fatalf("expected ProxyEnable=0, got %d", dw)
	}
	valServer, _ := store.ReadValue(KeyProxyServer)
	if valServer.Exists {
		t.Fatal("expected ProxyServer to be deleted on original restore")
	}
}

func TestManagerMandatoryRefusalOnMissingBackup(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentBackup := filepath.Join(tempDir, "missing_backup.json")
	store := newMockStore()
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(1), // currently active
	}
	store.values[KeyProxyServer] = RegistryValue{
		Exists: true,
		Type:   REG_SZ,
		Data:   EncodeString("http=127.0.0.1:1080;https=127.0.0.1:1080"),
	}

	mgr := NewManager(store)

	// Even with force=true, missing backup must MANDATORILY REFUSE and NOT modify registry
	_, err := mgr.Restore(nonExistentBackup, true)
	if err == nil {
		t.Fatal("expected Restore to fail on missing backup, got nil")
	}
	if !errors.Is(err, ErrNoBackupFound) {
		t.Fatalf("expected ErrNoBackupFound, got: %v", err)
	}

	// Verify registry was NOT modified
	currEnable, _ := store.ReadValue(KeyProxyEnable)
	dw, _ := DecodeDWORD(currEnable.Data)
	if dw != 1 {
		t.Fatalf("registry ProxyEnable was modified despite missing backup refusal: got %d", dw)
	}
}

func TestManagerMandatoryRefusalOnCorruptBackup(t *testing.T) {
	tempDir := t.TempDir()
	corruptBackup := filepath.Join(tempDir, "corrupt_backup.json")
	if err := os.WriteFile(corruptBackup, []byte("{not valid json..."), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	store := newMockStore()
	mgr := NewManager(store)

	// Even with force=true, corrupt backup must MANDATORILY REFUSE and NOT modify registry
	_, err := mgr.Restore(corruptBackup, true)
	if err == nil {
		t.Fatal("expected Restore to fail on corrupt backup, got nil")
	}
	if !errors.Is(err, ErrCorruptBackup) {
		t.Fatalf("expected ErrCorruptBackup, got: %v", err)
	}
}

func TestManagerIdempotentRestoration(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	// Enable
	if _, err := mgr.Enable("127.0.0.1:1080", backupPath); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Disable (first time)
	res1, err := mgr.Disable(backupPath, false)
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if !res1.Success {
		t.Fatalf("expected success, got: %+v", res1)
	}

	// Create a backup file that already matches original state (simulating interrupted run after restore)
	b := &Backup{
		Version:   1,
		Timestamp: time.Now().UTC(),
		PID:       1234,
		Original: map[string]RegistryValue{
			KeyProxyEnable: {Exists: true, Type: REG_DWORD, Data: EncodeDWORD(0)},
			KeyProxyServer: {Exists: false},
		},
		Applied: map[string]RegistryValue{
			KeyProxyEnable: {Exists: true, Type: REG_DWORD, Data: EncodeDWORD(1)},
			KeyProxyServer: {Exists: true, Type: REG_SZ, Data: EncodeString("http=127.0.0.1:1080;https=127.0.0.1:1080")},
		},
	}
	if err := mgr.writeAndVerifyBackup(backupPath, b); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// Run Restore again: should succeed idempotently
	res2, err := mgr.Restore(backupPath, false)
	if err != nil {
		t.Fatalf("idempotent Restore failed: %v", err)
	}
	if !res2.AlreadyRestored || !res2.BackupRetired {
		t.Fatalf("expected AlreadyRestored and BackupRetired true, got: %+v", res2)
	}
}

func TestManagerPartialWriteRollback(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}
	store.values[KeyProxyServer] = RegistryValue{
		Exists: true,
		Type:   REG_SZ,
		Data:   EncodeString("initial.proxy:8080"),
	}

	// Inject error on the first write to ProxyEnable (the second write during Enable)
	failedOnce := false
	store.writeErrHook = func(name string) error {
		if name == KeyProxyEnable && !failedOnce {
			failedOnce = true
			return errors.New("simulated access denied writing ProxyEnable")
		}
		return nil
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	_, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err == nil {
		t.Fatal("expected Enable to fail on injected write error, got nil")
	}
	if !strings.Contains(err.Error(), "safely rolled back") {
		t.Fatalf("expected error to indicate safe rollback, got: %v", err)
	}

	// Verify rollback restored ProxyServer to initial.proxy:8080
	currSrv, _ := store.ReadValue(KeyProxyServer)
	currStr, _ := DecodeString(currSrv.Data)
	if currStr != "initial.proxy:8080" {
		t.Fatalf("ProxyServer was not rolled back: got %q", currStr)
	}

	// Verify backup file was removed since rollback succeeded cleanly
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatal("expected backup file to be removed after successful rollback")
	}
}

func TestManagerPartialWriteRollbackFailure(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.values[KeyProxyEnable] = RegistryValue{
		Exists: true,
		Type:   REG_DWORD,
		Data:   EncodeDWORD(0),
	}

	// Persistently fail writes to ProxyEnable, so both activation and rollback fail
	store.writeErrHook = func(name string) error {
		if name == KeyProxyEnable {
			return errors.New("persistent permission denied on ProxyEnable")
		}
		return nil
	}

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	_, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err == nil {
		t.Fatal("expected Enable to fail, got nil")
	}
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("expected ErrRollbackFailed when rollback cannot complete, got: %v", err)
	}

	// Backup file must be RETAINED when rollback fails
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatal("backup file must be retained when rollback fails, but was removed")
	}
}

func TestManagerNotificationFailureSurfaced(t *testing.T) {
	tempDir := t.TempDir()
	backupPath := filepath.Join(tempDir, "sysproxy_backup.json")
	store := newMockStore()
	store.notifyErr = errors.New("simulated WinINet notification broadcast failure")

	mgr := NewManager(store)
	mgr.DialFunc = reachableDialer

	res, err := mgr.Enable("127.0.0.1:1080", backupPath)
	if err != nil {
		t.Fatalf("Enable should succeed despite notification error: %v", err)
	}
	if res.NotificationWarning == "" {
		t.Fatal("expected NotificationWarning to be populated, got empty string")
	}
	if !strings.Contains(res.NotificationWarning, "simulated WinINet notification") {
		t.Fatalf("unexpected warning content: %q", res.NotificationWarning)
	}
}

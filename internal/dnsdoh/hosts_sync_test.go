package dnsdoh

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type mockHostsResolver struct {
	lookupFn func(ctx context.Context, host string) ([]net.IP, error)
}

func (m *mockHostsResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, host)
	}
	return nil, errors.New("not implemented")
}

func TestSyncAndRemoveManagedHosts(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	var flushCount atomic.Int32
	hostsFileMu.Lock()
	origPath := hostsFilePath
	origFlush := flushDNSFunc
	hostsFilePath = tmpHosts
	flushDNSFunc = func() error {
		flushCount.Add(1)
		return nil
	}
	hostsFileMu.Unlock()

	t.Cleanup(func() {
		hostsFileMu.Lock()
		hostsFilePath = origPath
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	initialCustomContent := strings.Join([]string{
		"# Custom Windows hosts file",
		"127.0.0.1       localhost",
		"10.20.30.40     internal.corp.local",
	}, "\r\n") + "\r\n"

	if err := os.WriteFile(tmpHosts, []byte(initialCustomContent), 0644); err != nil {
		t.Fatalf("write initial hosts file: %v", err)
	}

	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			switch host {
			case "discord.com":
				// First IP is ISP sinkhole 195.175.254.2; must skip and pick 162.159.138.232
				return []net.IP{
					net.ParseIP("195.175.254.2"),
					net.ParseIP("162.159.138.232"),
				}, nil
			case "updates.discord.com":
				// Simulate DoH timeout -> must use Cloudflare fallback 162.159.135.232
				return nil, context.DeadlineExceeded
			case "cdn.discordapp.com":
				// Simulate only sinkhole returned -> must use Cloudflare fallback 162.159.130.233
				return []net.IP{net.ParseIP("195.175.254.2")}, nil
			default:
				if strings.HasSuffix(host, "roblox.com") {
					return []net.IP{net.ParseIP("128.116.102.3")}, nil
				}
				return []net.IP{net.ParseIP("162.159.136.232")}, nil
			}
		},
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 1. First SyncManagedHosts
	if err := SyncManagedHosts(context.Background(), resolver, logger); err != nil {
		t.Fatalf("SyncManagedHosts failed: %v", err)
	}

	if flushCount.Load() != 1 {
		t.Errorf("expected flushDNSFunc called once, got %d", flushCount.Load())
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "synced clean DoH IPs to Windows hosts file") {
		t.Errorf("expected INFO log 'synced clean DoH IPs to Windows hosts file', got: %s", logOutput)
	}

	syncedBytes, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced hosts file: %v", err)
	}
	syncedContent := string(syncedBytes)

	// Verify custom user lines are preserved
	if !strings.Contains(syncedContent, "10.20.30.40     internal.corp.local") {
		t.Errorf("custom host line was not preserved in:\n%s", syncedContent)
	}
	// Verify sinkhole IP was never written
	if strings.Contains(syncedContent, SinkholeIPv4) {
		t.Errorf("sinkhole IP %s must never appear in hosts file:\n%s", SinkholeIPv4, syncedContent)
	}
	// Verify non-sinkhole DoH IP was selected for discord.com
	if !strings.Contains(syncedContent, "162.159.138.232 discord.com") {
		t.Errorf("expected '162.159.138.232 discord.com' in:\n%s", syncedContent)
	}
	// Verify fallback IPs were used for timed-out / poisoned queries
	if !strings.Contains(syncedContent, "162.159.135.232 updates.discord.com") {
		t.Errorf("expected fallback '162.159.135.232 updates.discord.com' in:\n%s", syncedContent)
	}
	if !strings.Contains(syncedContent, "162.159.130.233 cdn.discordapp.com") {
		t.Errorf("expected fallback '162.159.130.233 cdn.discordapp.com' in:\n%s", syncedContent)
	}
	// Verify Roblox domain was included
	if !strings.Contains(syncedContent, "128.116.102.3 www.roblox.com") {
		t.Errorf("expected '128.116.102.3 www.roblox.com' in:\n%s", syncedContent)
	}

	// 2. Second SyncManagedHosts with updated IP (verify idempotent update without duplicate blocks)
	resolver2 := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.137.232")}, nil
		},
	}
	if err := SyncManagedHosts(context.Background(), resolver2, logger); err != nil {
		t.Fatalf("second SyncManagedHosts failed: %v", err)
	}

	resyncedBytes, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read resynced hosts file: %v", err)
	}
	resyncedContent := string(resyncedBytes)

	if strings.Count(resyncedContent, BeginManagedHostsMarker) != 1 {
		t.Errorf("expected exactly 1 begin marker, got %d", strings.Count(resyncedContent, BeginManagedHostsMarker))
	}
	if strings.Count(resyncedContent, EndManagedHostsMarker) != 1 {
		t.Errorf("expected exactly 1 end marker, got %d", strings.Count(resyncedContent, EndManagedHostsMarker))
	}
	if !strings.Contains(resyncedContent, "162.159.137.232 discord.com") {
		t.Errorf("expected updated IP '162.159.137.232 discord.com' in:\n%s", resyncedContent)
	}
	if strings.Contains(resyncedContent, "162.159.138.232 discord.com") {
		t.Errorf("old managed IP '162.159.138.232 discord.com' was not replaced")
	}

	// 3. RemoveManagedHosts restores original custom lines cleanly
	if err := RemoveManagedHosts(); err != nil {
		t.Fatalf("RemoveManagedHosts failed: %v", err)
	}

	restoredBytes, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read restored hosts file: %v", err)
	}
	restoredContent := string(restoredBytes)

	if strings.Contains(restoredContent, BeginManagedHostsMarker) || strings.Contains(restoredContent, EndManagedHostsMarker) {
		t.Errorf("managed markers still present after RemoveManagedHosts:\n%s", restoredContent)
	}
	if strings.Contains(restoredContent, "discord.com") {
		t.Errorf("managed domain entries still present after RemoveManagedHosts:\n%s", restoredContent)
	}
	if restoredContent != initialCustomContent {
		t.Errorf("restored content mismatch:\ngot:\n%q\nwant:\n%q", restoredContent, initialCustomContent)
	}
}

type mockQueryTypeHostsResolver struct {
	lookupCalls atomic.Int32
}

func (m *mockQueryTypeHostsResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	m.lookupCalls.Add(1)
	return []net.IP{net.ParseIP(SinkholeIPv4)}, nil
}

func (m *mockQueryTypeHostsResolver) ResolveQueryType(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
	if domain == "discord.com" {
		return []net.IP{net.ParseIP("162.159.138.232")}, 60 * time.Second, false, nil
	}
	return nil, 0, false, context.DeadlineExceeded
}

func TestSyncManagedHosts_QueryTypeResolverDoesNotFallbackToLookupIP(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "hosts")
	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	qtr := &mockQueryTypeHostsResolver{}
	if err := SyncManagedHostsFile(context.Background(), tmpFile, qtr, nil); err != nil {
		t.Fatalf("SyncManagedHostsFile failed: %v", err)
	}
	if qtr.lookupCalls.Load() != 0 {
		t.Errorf("expected 0 LookupIP calls when ResolveQueryType is implemented, got %d", qtr.lookupCalls.Load())
	}
}

func TestHostsBackupBeforeFirstModification(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")
	backupPath := HostsBackupPath(tmpHosts)

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	initialContent := "# Original System Hosts\r\n127.0.0.1 localhost\r\n192.168.1.50 printer.local\r\n"
	if err := os.WriteFile(tmpHosts, []byte(initialContent), 0644); err != nil {
		t.Fatalf("write initial hosts: %v", err)
	}

	// 1. Verify backup does not exist prior to sync
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatalf("backup should not exist before first sync")
	}

	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.135.232")}, nil
		},
	}

	// 2. First sync creates backup
	if err := SyncManagedHostsFile(context.Background(), tmpHosts, resolver, nil); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup file after first sync: %v", err)
	}
	if string(backupBytes) != initialContent {
		t.Fatalf("backup content mismatch:\ngot:\n%q\nwant:\n%q", string(backupBytes), initialContent)
	}

	// 3. Second sync with different data should NOT overwrite original backup
	resolver2 := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.99.99")}, nil
		},
	}
	if err := SyncManagedHostsFile(context.Background(), tmpHosts, resolver2, nil); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	backupBytes2, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup file after second sync: %v", err)
	}
	if string(backupBytes2) != initialContent {
		t.Fatalf("backup content was overwritten on second sync:\ngot:\n%q\nwant:\n%q", string(backupBytes2), initialContent)
	}

	// 4. Removal retires the backup
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatalf("backup file should be retired after clean removal")
	}

	restoredBytes, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read restored hosts: %v", err)
	}
	if string(restoredBytes) != initialContent {
		t.Fatalf("restored hosts mismatch:\ngot:\n%q\nwant:\n%q", string(restoredBytes), initialContent)
	}
}

func TestHostsOnlyTouchesManagedBlockWithSurroundingContent(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	// Intentionally create a file where custom lines exist BEFORE and AFTER the managed block
	initialCustom := strings.Join([]string{
		"# Header comment",
		"127.0.0.1 localhost",
		"::1 localhost",
		"# Trailing custom comment",
		"10.0.0.1 devbox",
	}, "\r\n") + "\r\n"

	if err := os.WriteFile(tmpHosts, []byte(initialCustom), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.135.232")}, nil
		},
	}

	if err := SyncManagedHostsFile(context.Background(), tmpHosts, resolver, nil); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	// Verify all initial lines exist
	synced, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced: %v", err)
	}
	syncedStr := string(synced)
	if !strings.Contains(syncedStr, "# Header comment") || !strings.Contains(syncedStr, "10.0.0.1 devbox") {
		t.Fatalf("custom content corrupted by sync:\n%s", syncedStr)
	}

	// Now remove
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	cleaned, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read cleaned: %v", err)
	}
	cleanedStr := string(cleaned)
	if strings.Contains(cleanedStr, BeginManagedHostsMarker) || strings.Contains(cleanedStr, EndManagedHostsMarker) {
		t.Fatalf("managed markers lingering in:\n%s", cleanedStr)
	}
	if cleanedStr != initialCustom {
		t.Fatalf("content outside managed block was modified:\ngot:\n%q\nwant:\n%q", cleanedStr, initialCustom)
	}
}

func TestRemoveManagedHostsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	initial := "127.0.0.1 localhost\r\n"
	if err := os.WriteFile(tmpHosts, []byte(initial), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	// 1. Remove on clean file is a no-op
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove on clean file failed: %v", err)
	}
	data, _ := os.ReadFile(tmpHosts)
	if string(data) != initial {
		t.Fatalf("clean file was modified by remove: %q", string(data))
	}

	// 2. Sync then multiple removes
	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.135.232")}, nil
		},
	}
	if err := SyncManagedHostsFile(context.Background(), tmpHosts, resolver, nil); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := RemoveManagedHostsFile(tmpHosts); err != nil {
			t.Fatalf("remove iteration %d failed: %v", i, err)
		}
		curData, _ := os.ReadFile(tmpHosts)
		if string(curData) != initial {
			t.Fatalf("iteration %d content mismatch: %q", i, string(curData))
		}
	}
}

func TestHasManagedHostsDetection(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	// 1. Non-existent file
	has, err := HasManagedHostsFile(filepath.Join(tmpDir, "nonexistent"))
	if err != nil || has {
		t.Fatalf("expected (false, nil) for non-existent file, got (%v, %v)", has, err)
	}

	// 2. Clean file
	_ = os.WriteFile(tmpHosts, []byte("127.0.0.1 localhost\r\n"), 0644)
	has, err = HasManagedHostsFile(tmpHosts)
	if err != nil || has {
		t.Fatalf("expected (false, nil) for clean file, got (%v, %v)", has, err)
	}

	// 3. File with managed block
	withBlock := "127.0.0.1 localhost\r\n" + BeginManagedHostsMarker + "\r\n1.2.3.4 discord.com\r\n" + EndManagedHostsMarker + "\r\n"
	_ = os.WriteFile(tmpHosts, []byte(withBlock), 0644)
	has, err = HasManagedHostsFile(tmpHosts)
	if err != nil || !has {
		t.Fatalf("expected (true, nil) for file with managed block, got (%v, %v)", has, err)
	}
}

func TestCrashLeftoverAndCorruptedRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	// Case A: Corrupted managed block missing the END marker (e.g., hard crash mid-write)
	corrupted := strings.Join([]string{
		"127.0.0.1 localhost",
		BeginManagedHostsMarker,
		"1.2.3.4 partial-domain.com",
		// Missing END marker
	}, "\r\n") + "\r\n"

	if err := os.WriteFile(tmpHosts, []byte(corrupted), 0644); err != nil {
		t.Fatalf("write corrupted hosts: %v", err)
	}

	has, err := HasManagedHostsFile(tmpHosts)
	if err != nil || !has {
		t.Fatalf("expected detection of corrupted block, got (%v, %v)", has, err)
	}

	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove corrupted block failed: %v", err)
	}

	cleaned, _ := os.ReadFile(tmpHosts)
	cleanedStr := string(cleaned)
	if strings.Contains(cleanedStr, BeginManagedHostsMarker) || strings.Contains(cleanedStr, "partial-domain") {
		t.Fatalf("corrupted block lines lingered after remove:\n%s", cleanedStr)
	}
	if !strings.Contains(cleanedStr, "127.0.0.1 localhost") {
		t.Fatalf("user line before corrupted block was lost:\n%s", cleanedStr)
	}
}

func TestRestoreWhenHostsMissingButBackupExists(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")
	backupPath := HostsBackupPath(tmpHosts)

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	backupContent := "127.0.0.1 localhost\r\n10.0.0.99 server\r\n"
	if err := os.WriteFile(backupPath, []byte(backupContent), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// tmpHosts does NOT exist. RemoveManagedHostsFile should restore from backup!
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("RemoveManagedHostsFile failed: %v", err)
	}

	restored, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("hosts file not restored: %v", err)
	}
	if string(restored) != backupContent {
		t.Fatalf("restored content mismatch:\ngot:\n%q\nwant:\n%q", string(restored), backupContent)
	}
	if _, err := os.Stat(backupPath); err == nil {
		t.Fatalf("backup file should be retired after restoration")
	}
}

func TestSyncManagedHostsWithCustomDomains(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		},
	}

	customDomains := []string{"custom-target.internal", "my-service.net"}
	if err := SyncManagedHostsFileWithDomains(context.Background(), tmpHosts, resolver, nil, customDomains); err != nil {
		t.Fatalf("SyncManagedHostsFileWithDomains failed: %v", err)
	}

	data, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "1.2.3.4 custom-target.internal") || !strings.Contains(content, "1.2.3.4 my-service.net") {
		t.Fatalf("custom domains not written to hosts:\n%s", content)
	}
	// Verify discord.com is NOT present since custom domains were provided
	if strings.Contains(content, "discord.com") {
		t.Fatalf("default domain discord.com should not be present when custom list is specified:\n%s", content)
	}
}

func TestHostsBlockAddUpdateRemoveInPlace(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	// Initial file with custom lines before and after
	initialHeader := "# Custom corporate hosts header\r\n127.0.0.1 localhost\r\n::1 localhost\r\n"
	initialFooter := "# Custom trailing server entries\r\n192.168.1.100 nas.local\r\n10.0.0.50 devbox\r\n"
	initialContent := initialHeader + initialFooter

	if err := os.WriteFile(tmpHosts, []byte(initialContent), 0644); err != nil {
		t.Fatalf("write initial hosts: %v", err)
	}

	// 1. ADD: First sync adds managed block
	resolver1 := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.135.232")}, nil
		},
	}
	if err := SyncManagedHostsFileWithDomains(context.Background(), tmpHosts, resolver1, nil, []string{"discord.com"}); err != nil {
		t.Fatalf("first sync (add) failed: %v", err)
	}

	data1, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced 1: %v", err)
	}
	content1 := string(data1)
	if !strings.Contains(content1, "162.159.135.232 discord.com") {
		t.Fatalf("managed block not added:\n%s", content1)
	}

	// 2. UPDATE IN PLACE: Now insert a custom line AFTER the managed block to test in-place update
	withSurrounding := initialHeader + BeginManagedHostsMarker + "\r\n162.159.135.232 discord.com\r\n" + EndManagedHostsMarker + "\r\n" + initialFooter
	if err := os.WriteFile(tmpHosts, []byte(withSurrounding), 0644); err != nil {
		t.Fatalf("write withSurrounding: %v", err)
	}

	// Perform an update sync with new IP
	resolver2 := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.99.99")}, nil
		},
	}
	if err := SyncManagedHostsFileWithDomains(context.Background(), tmpHosts, resolver2, nil, []string{"discord.com"}); err != nil {
		t.Fatalf("second sync (update) failed: %v", err)
	}

	data2, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced 2: %v", err)
	}
	content2 := string(data2)

	// Verify new IP is in the managed block
	if !strings.Contains(content2, "162.159.99.99 discord.com") {
		t.Fatalf("managed block not updated with new IP:\n%s", content2)
	}

	// CRUCIAL: Verify that initialFooter is STILL AFTER the managed block!
	endIdx := strings.Index(content2, EndManagedHostsMarker)
	footerIdx := strings.Index(content2, "# Custom trailing server entries")
	if endIdx == -1 || footerIdx == -1 {
		t.Fatalf("missing end marker or footer in:\n%s", content2)
	}
	if footerIdx < endIdx {
		t.Fatalf("REGRESSION: footer was shifted BEFORE the managed block! endIdx=%d, footerIdx=%d\nFull content:\n%s", endIdx, footerIdx, content2)
	}

	// Also verify initialHeader is BEFORE the managed block
	beginIdx := strings.Index(content2, BeginManagedHostsMarker)
	headerIdx := strings.Index(content2, "# Custom corporate hosts header")
	if headerIdx > beginIdx {
		t.Fatalf("REGRESSION: header was shifted AFTER the managed block! beginIdx=%d, headerIdx=%d", beginIdx, headerIdx)
	}

	// 3. REMOVE: Remove managed hosts and verify surrounding content is intact
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	data3, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read after remove: %v", err)
	}
	content3 := string(data3)
	if strings.Contains(content3, BeginManagedHostsMarker) || strings.Contains(content3, EndManagedHostsMarker) {
		t.Fatalf("managed markers lingering in:\n%s", content3)
	}
	if !strings.Contains(content3, "# Custom corporate hosts header") || !strings.Contains(content3, "# Custom trailing server entries") {
		t.Fatalf("surrounding content lost after remove:\n%s", content3)
	}
}

func TestHostsReadOnlyFileHandling(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	initial := "127.0.0.1 localhost\r\n"
	if err := os.WriteFile(tmpHosts, []byte(initial), 0644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	// Set file as read-only
	if err := os.Chmod(tmpHosts, 0444); err != nil {
		t.Fatalf("chmod read-only: %v", err)
	}

	resolver := &mockHostsResolver{
		lookupFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("162.159.135.232")}, nil
		},
	}

	// Sync should handle/clear read-only attribute and succeed
	if err := SyncManagedHostsFileWithDomains(context.Background(), tmpHosts, resolver, nil, []string{"discord.com"}); err != nil {
		t.Fatalf("sync on read-only hosts file failed: %v", err)
	}

	data, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read synced: %v", err)
	}
	if !strings.Contains(string(data), "162.159.135.232 discord.com") {
		t.Fatalf("managed block not written to read-only hosts file:\n%s", string(data))
	}

	// Mark read-only again
	_ = os.Chmod(tmpHosts, 0444)

	// Removal should also succeed on read-only file
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("remove on read-only hosts file failed: %v", err)
	}
}

func TestHostsEmptyFileRestoresFromBackup(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")
	backupPath := HostsBackupPath(tmpHosts)

	hostsFileMu.Lock()
	origFlush := flushDNSFunc
	flushDNSFunc = func() error { return nil }
	hostsFileMu.Unlock()
	t.Cleanup(func() {
		hostsFileMu.Lock()
		flushDNSFunc = origFlush
		hostsFileMu.Unlock()
	})

	// Create 0-byte hosts file (simulating corruption / truncation)
	if err := os.WriteFile(tmpHosts, []byte{}, 0644); err != nil {
		t.Fatalf("write 0-byte hosts: %v", err)
	}

	// Create valid backup file
	backupContent := "127.0.0.1 localhost\r\n192.168.1.1 gateway\r\n"
	if err := os.WriteFile(backupPath, []byte(backupContent), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// Calling RemoveManagedHostsFile on a 0-byte hosts file should NOT delete the backup;
	// it must restore from backup!
	if err := RemoveManagedHostsFile(tmpHosts); err != nil {
		t.Fatalf("RemoveManagedHostsFile failed on empty hosts file: %v", err)
	}

	data, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("read restored hosts: %v", err)
	}
	if string(data) != backupContent {
		t.Fatalf("empty hosts was not restored from backup:\ngot:\n%q\nwant:\n%q", string(data), backupContent)
	}
}

func TestHasHostsBackupDetection(t *testing.T) {
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")
	backupPath := HostsBackupPath(tmpHosts)

	// 1. No backup
	has, err := HasHostsBackupFile(tmpHosts)
	if err != nil || has {
		t.Fatalf("expected (false, nil) when no backup exists, got (%v, %v)", has, err)
	}

	// 2. Create backup
	_ = os.WriteFile(backupPath, []byte("127.0.0.1 localhost\r\n"), 0644)
	has, err = HasHostsBackupFile(tmpHosts)
	if err != nil || !has {
		t.Fatalf("expected (true, nil) when backup exists, got (%v, %v)", has, err)
	}
}




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


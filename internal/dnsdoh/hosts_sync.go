package dnsdoh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultHostsPath is the standard Windows system hosts file location.
	DefaultHostsPath = `C:\Windows\System32\drivers\etc\hosts`
	// BeginManagedHostsMarker marks the start of the dpibypass managed hosts section.
	BeginManagedHostsMarker = "# BEGIN DPIBYPASS MANAGED HOSTS"
	// EndManagedHostsMarker marks the end of the dpibypass managed hosts section.
	EndManagedHostsMarker = "# END DPIBYPASS MANAGED HOSTS"
	// SinkholeIPv4 is the Türk Telekom / BTK DNS sinkhole IPv4 address.
	SinkholeIPv4 = "195.175.254.2"
)

var (
	hostsFileMu   sync.Mutex
	hostsFilePath = DefaultHostsPath
	flushDNSFunc  = defaultFlushDNS
)

// ManagedDomains lists the core Discord and Roblox domains synced via DoH on startup.
var ManagedDomains = []string{
	// Discord
	"discord.com",
	"www.discord.com",
	"updates.discord.com",
	"gateway.discord.gg",
	"cdn.discordapp.com",
	"media.discordapp.net",
	"images-ext-1.discordapp.net",
	"images-ext-2.discordapp.net",
	"dl.discordapp.net",
	"dl2.discordapp.net",
	"status.discord.com",
	"discord.gg",
	"discordapp.com",
	"discordapp.net",
	"discord.media",
	"latency.discord.media",
	"ptb.discord.com",
	"canary.discord.com",
	"remote-auth-gateway.discord.gg",
	"status.discordapp.com",
	"router.discordapp.net",
	"api.discord.com",
	"cdn.discord.com",
	// Roblox
	"roblox.com",
	"www.roblox.com",
	"auth.roblox.com",
	"apis.roblox.com",
	"users.roblox.com",
	"games.roblox.com",
	"assetdelivery.roblox.com",
	"economy.roblox.com",
	"thumbnails.roblox.com",
	"presence.roblox.com",
	"clientsettings.roblox.com",
	"clientsettingscdn.roblox.com",
	"ecs.roblox.com",
	"client-telemetry.roblox.com",
	"realtime.roblox.com",
	"lms.roblox.com",
	"friends.roblox.com",
	"groups.roblox.com",
	"catalog.roblox.com",
	"avatar.roblox.com",
	"chat.roblox.com",
	"accountsettings.roblox.com",
	"locale.roblox.com",
}

// FallbackDomainIPs provides verified Cloudflare Anycast IPv4 addresses if a startup DoH query times out.
var FallbackDomainIPs = map[string]string{
	"discord.com":                    "162.159.135.232",
	"www.discord.com":                "162.159.135.232",
	"updates.discord.com":            "162.159.135.232",
	"gateway.discord.gg":             "162.159.135.232",
	"status.discord.com":             "162.159.135.232",
	"discord.gg":                     "162.159.135.232",
	"discordapp.com":                 "162.159.135.232",
	"discord.media":                  "162.159.135.232",
	"latency.discord.media":          "162.159.135.232",
	"ptb.discord.com":                "162.159.135.232",
	"canary.discord.com":             "162.159.135.232",
	"remote-auth-gateway.discord.gg": "162.159.135.232",
	"status.discordapp.com":          "162.159.135.232",
	"api.discord.com":                "162.159.135.232",
	"cdn.discord.com":                "162.159.130.233",
	"cdn.discordapp.com":             "162.159.130.233",
	"media.discordapp.net":           "162.159.130.233",
	"images-ext-1.discordapp.net":    "162.159.130.233",
	"images-ext-2.discordapp.net":    "162.159.130.233",
	"dl.discordapp.net":              "162.159.130.233",
	"dl2.discordapp.net":             "162.159.130.233",
	"router.discordapp.net":          "162.159.130.233",
	"discordapp.net":                 "162.159.130.233",
}

type queryTypeResolver interface {
	ResolveQueryType(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error)
}

func defaultFlushDNS() error {
	return exec.Command("ipconfig", "/flushdns").Run()
}

// SyncManagedHosts resolves live IPv4 (A) records via dohResolver for all core Discord and Roblox
// domains, writes them into the managed section of the Windows hosts file, and flushes the OS DNS cache.
func SyncManagedHosts(ctx context.Context, dohResolver Resolver, logger *slog.Logger) error {
	hostsFileMu.Lock()
	targetPath := hostsFilePath
	hostsFileMu.Unlock()
	return SyncManagedHostsFile(ctx, targetPath, dohResolver, logger)
}

// SyncManagedHostsFile resolves live IPv4 (A) records via dohResolver and atomically updates
// the managed section in the specified hosts file path.
func SyncManagedHostsFile(ctx context.Context, targetPath string, dohResolver Resolver, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resolved := make([]string, len(ManagedDomains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for i, domain := range ManagedDomains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				if fb, ok := FallbackDomainIPs[d]; ok {
					resolved[idx] = fb
				}
				return
			}

			ipStr := resolveCleanIPv4(ctx, dohResolver, d)
			if ipStr == "" {
				if fb, ok := FallbackDomainIPs[d]; ok {
					ipStr = fb
				}
			}
			resolved[idx] = ipStr
		}(i, domain)
	}
	wg.Wait()

	var managedLines []string
	managedLines = append(managedLines, BeginManagedHostsMarker)
	entriesCount := 0
	for i, domain := range ManagedDomains {
		ipStr := resolved[i]
		if ipStr == "" {
			continue
		}
		managedLines = append(managedLines, fmt.Sprintf("%s %s", ipStr, domain))
		entriesCount++
	}
	managedLines = append(managedLines, EndManagedHostsMarker)

	hostsFileMu.Lock()
	defer hostsFileMu.Unlock()

	existingData, err := os.ReadFile(targetPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hosts file %q: %w", targetPath, err)
	}

	preservedLines, _ := stripManagedBlockLines(string(existingData))
	var outLines []string
	outLines = append(outLines, preservedLines...)
	outLines = append(outLines, managedLines...)

	content := strings.Join(outLines, "\r\n") + "\r\n"
	if err := writeHostsFileAtomic(targetPath, []byte(content)); err != nil {
		return fmt.Errorf("update hosts file %q: %w", targetPath, err)
	}

	_ = flushDNSFunc()

	logger.Info("synced clean DoH IPs to Windows hosts file", "entries", entriesCount)
	return nil
}

// RemoveManagedHosts removes the dpibypass managed section from the Windows hosts file
// while preserving all user lines outside that block, and flushes the OS DNS cache.
func RemoveManagedHosts() error {
	hostsFileMu.Lock()
	targetPath := hostsFilePath
	hostsFileMu.Unlock()
	return RemoveManagedHostsFile(targetPath)
}

// RemoveManagedHostsFile removes the dpibypass managed section from the specified hosts file.
func RemoveManagedHostsFile(targetPath string) error {
	hostsFileMu.Lock()
	defer hostsFileMu.Unlock()

	existingData, err := os.ReadFile(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read hosts file %q: %w", targetPath, err)
	}

	preservedLines, foundBlock := stripManagedBlockLines(string(existingData))
	if !foundBlock {
		return nil
	}

	var content string
	if len(preservedLines) > 0 {
		content = strings.Join(preservedLines, "\r\n") + "\r\n"
	}

	if err := writeHostsFileAtomic(targetPath, []byte(content)); err != nil {
		return fmt.Errorf("restore hosts file %q: %w", targetPath, err)
	}

	_ = flushDNSFunc()
	return nil
}

func resolveCleanIPv4(ctx context.Context, dohResolver Resolver, domain string) string {
	if dohResolver == nil {
		return ""
	}
	queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	var ips []net.IP
	if qtr, ok := dohResolver.(queryTypeResolver); ok {
		resIPs, _, _, err := qtr.ResolveQueryType(queryCtx, domain, TypeA)
		if err == nil && len(resIPs) > 0 {
			ips = resIPs
		}
	} else {
		resIPs, err := dohResolver.LookupIP(queryCtx, domain)
		if err == nil {
			ips = resIPs
		}
	}

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsUnspecified() || ip4.IsLoopback() {
			continue
		}
		s := ip4.String()
		if s == SinkholeIPv4 {
			continue
		}
		return s
	}
	return ""
}

func stripManagedBlockLines(content string) ([]string, bool) {
	if content == "" {
		return nil, false
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	rawLines := strings.Split(normalized, "\n")

	var preserved []string
	inBlock := false
	foundBlock := false

	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == BeginManagedHostsMarker {
			inBlock = true
			foundBlock = true
			continue
		}
		if trimmed == EndManagedHostsMarker {
			inBlock = false
			continue
		}
		if !inBlock {
			preserved = append(preserved, line)
		}
	}

	// Trim trailing empty line caused by final newline split so repeated syncs do not accumulate blank lines
	for len(preserved) > 0 && preserved[len(preserved)-1] == "" {
		preserved = preserved[:len(preserved)-1]
	}

	return preserved, foundBlock
}

func writeHostsFileAtomic(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmpPath := targetPath + ".dpibypass.tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err == nil {
		if renameErr := os.Rename(tmpPath, targetPath); renameErr == nil {
			return nil
		}
		_ = os.Remove(tmpPath)
	}
	return os.WriteFile(targetPath, data, 0644)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dpibypass/internal/app"
	"dpibypass/internal/config"
	"dpibypass/internal/diagnostics"
	"dpibypass/internal/divert"
	"dpibypass/internal/dnsdoh"
	"dpibypass/internal/logging"
	"dpibypass/internal/strategy"
	"dpibypass/internal/sysproxy"
	"dpibypass/internal/tuner"
	"dpibypass/internal/webui"
)

var (
	version   = "1.0.0-phase1"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	if commit != "none" || buildDate != "unknown" {
		fmt.Printf("dpibypass version %s (commit: %s, built: %s)\n", version, commit, buildDate)
	} else {
		fmt.Printf("dpibypass version %s\n", version)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("command required")
	}

	cmd := args[0]
	cmdArgs := args[1:]

	var cmdErr error
	switch cmd {
	case "run":
		cmdErr = executeRun(cmdArgs)
	case "check":
		cmdErr = executeCheck(cmdArgs)
	case "tune":
		cmdErr = executeTune(cmdArgs)
	case "config":
		cmdErr = executeConfig(cmdArgs)
	case "recover":
		cmdErr = executeRecover(cmdArgs)
	case "sysproxy":
		cmdErr = executeSysproxy(cmdArgs)
	case "version", "-v", "--version":
		printVersion()
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", cmd)
	}

	if errors.Is(cmdErr, flag.ErrHelp) {
		return nil
	}
	return cmdErr
}

func resolveConfig(configPath string) (*config.Config, string, error) {
	if configPath != "" {
		cfg, err := config.Load(configPath)
		return cfg, configPath, err
	}
	if _, statErr := os.Stat("config.json"); statErr == nil {
		cfg, err := config.Load("config.json")
		return cfg, "config.json", err
	}
	cfg := config.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("default configuration invalid: %w", err)
	}
	return cfg, "", nil
}

func executeRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass run [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to JSON configuration file (optional; uses defaults if omitted)")
	modeFlag := fs.String("mode", "", "engine mode: 'proxy' (Phase 1 loopback proxy) or 'packet' (Phase 2 WinDivert interception)")
	fakeModeFlag := fs.String("fake-mode", "", "fake packet evasion mode: 'none', 'ttl', 'multi-ttl', 'wrong-chksum', or 'both'")
	fakeTTLFlag := fs.Int("fake-ttl", 0, "fake packet IPv4 TTL hop count (2..16, default 4)")
	fakeSNIFlag := fs.String("fake-sni", "", "fake TLS ClientHello dummy SNI (default 'www.example.com')")
	fakeDelayMSFlag := fs.Int("fake-delay-ms", -1, "delay in milliseconds between fake packet and real packet (default 0)")
	splitOffsetFlag := fs.String("split-offset", "", "out-of-order split offset: 'sni-start', 'sni-mid', 'sni-end', or numeric byte offset")
	delayMSFlag := fs.Int("delay-ms", -1, "inter-packet delay in milliseconds between split segments (default 0)")
	dropQUICFlag := fs.Bool("drop-quic", true, "drop outbound UDP/443 packets to force TCP fallback in packet mode")
	interceptDNSFlag := fs.Bool("intercept-dns", false, "intercept outbound UDP/53 DNS queries and resolve via DoH")
	autoLearnFlag := fs.Bool("auto-learn", true, "enable automatic TCP retransmission block detection, strategy escalation, and learned domain persistence")
	noAutoLearnFlag := fs.Bool("no-autolearn", false, "disable automatic TCP retransmission auto-learning")
	noAutoLearnHyphenFlag := fs.Bool("no-auto-learn", false, "disable automatic TCP retransmission auto-learning")
	autoLearnPathFlag := fs.String("auto-learn-path", "", "path to autolearn.json for persisting learned evasion strategies")
	durationFlag := fs.Int("duration-s", 0, "run engine for a fixed duration in seconds before shutting down (0 = run indefinitely until Ctrl+C)")
	stopFileFlag := fs.String("stop-file", "", "path to a file; when created, dpibypass stops gracefully")
	webuiFlag := fs.String("webui", "", "optional loopback address for embedded WebUI dashboard (e.g. 127.0.0.1:8787)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	cfg, _, err := resolveConfig(*configPath)
	if err != nil {
		return fmt.Errorf("resolve configuration: %w", err)
	}

	// Apply CLI flag overrides
	if *modeFlag != "" {
		cfg.Mode = *modeFlag
	}
	if *fakeModeFlag != "" {
		cfg.Packet.FakePacketMode = *fakeModeFlag
	}
	if *fakeTTLFlag > 0 {
		cfg.Packet.FakeTTL = *fakeTTLFlag
	}
	if *fakeSNIFlag != "" {
		cfg.Packet.FakeSNI = *fakeSNIFlag
	}
	if *fakeDelayMSFlag >= 0 {
		cfg.Packet.FakeDelayMS = *fakeDelayMSFlag
	}
	if *splitOffsetFlag != "" {
		cfg.Packet.SplitOffset = *splitOffsetFlag
	}
	if *delayMSFlag >= 0 {
		cfg.Packet.InterPacketDelayMS = *delayMSFlag
	}

	dropQUICProvided := false
	interceptDNSProvided := false
	autoLearnProvided := false
	explicitOverrides := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "drop-quic" {
			dropQUICProvided = true
		}
		if f.Name == "intercept-dns" {
			interceptDNSProvided = true
		}
		if f.Name == "auto-learn" {
			autoLearnProvided = true
		}
		if f.Name == "fake-mode" || f.Name == "fake-ttl" || f.Name == "split-offset" || f.Name == "delay-ms" {
			explicitOverrides = true
		}
	})
	if dropQUICProvided {
		val := *dropQUICFlag
		cfg.Packet.DropQUIC = &val
	}
	if interceptDNSProvided {
		val := *interceptDNSFlag
		cfg.Packet.InterceptDNS = &val
	}
	if autoLearnProvided {
		val := *autoLearnFlag
		cfg.Packet.AutoLearn = &val
	}
	if *noAutoLearnFlag || *noAutoLearnHyphenFlag {
		val := false
		cfg.Packet.AutoLearn = &val
	}
	if *autoLearnPathFlag != "" {
		cfg.Packet.AutoLearnPath = *autoLearnPathFlag
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	logger, err := logging.New(cfg.LogLevel, os.Stderr)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if *durationFlag > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, time.Duration(*durationFlag)*time.Second)
		defer cancelTimeout()
	}

	if *stopFileFlag != "" {
		stopPath := *stopFileFlag
		_ = os.Remove(stopPath)
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(stopPath); err == nil {
						_ = os.Remove(stopPath)
						cancel()
						return
					}
				}
			}
		}()
	}

	if cfg.Mode == config.ModePacket {
		return executeRunPacket(ctx, cfg, logger, *webuiFlag, explicitOverrides)
	}
	return executeRunProxy(ctx, cfg, logger, *webuiFlag)
}

type proxyWebUIController struct {
	app *app.App
	cfg *config.Config
}

func (c *proxyWebUIController) Mode() string     { return "proxy" }
func (c *proxyWebUIController) Strategy() string { return c.cfg.DefaultProfile }
func (c *proxyWebUIController) DriverState() string {
	return "NOT_APPLICABLE"
}
func (c *proxyWebUIController) IsPaused() bool { return false }
func (c *proxyWebUIController) Pause() error {
	return errors.New("driver pause is only applicable in packet mode")
}
func (c *proxyWebUIController) Resume() error { return nil }
func (c *proxyWebUIController) LearnedDomains() []webui.LearnedDomainInfo {
	return nil
}
func (c *proxyWebUIController) Stats() webui.WebUIStats {
	return webui.WebUIStats{
		PacketsRecv: uint64(c.app.ActiveConnections()),
	}
}

func executeRunProxy(ctx context.Context, cfg *config.Config, logger *slog.Logger, webuiAddr string) error {
	application, err := app.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialize application: %w", err)
	}

	if webuiAddr != "" {
		ctrl := &proxyWebUIController{app: application, cfg: cfg}
		webuiServer, err := webui.NewServer(webuiAddr, ctrl, logger)
		if err != nil {
			return fmt.Errorf("initialize webui: %w", err)
		}
		go func() {
			if err := webuiServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("webui server error", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = webuiServer.Shutdown(shutdownCtx)
		}()
	}

	return application.Run(ctx)
}

type packetWebUIController struct {
	harness *divert.Harness
	cfg     *config.Config
}

func (c *packetWebUIController) Mode() string { return "packet" }
func (c *packetWebUIController) Strategy() string {
	strat := "Out-of-Order Split"
	if c.cfg.Packet.SplitOffset != "" {
		strat = fmt.Sprintf("OOO Split (%s)", c.cfg.Packet.SplitOffset)
	}
	if c.cfg.Packet.FakePacketMode != "" && c.cfg.Packet.FakePacketMode != "none" {
		strat = fmt.Sprintf("TTL %d + %s", c.cfg.Packet.FakeTTL, strat)
	}
	return strat
}
func (c *packetWebUIController) DriverState() string {
	if c.harness.IsPaused() {
		return "STOPPED (PAUSED)"
	}
	st := divert.QueryDriverStatus()
	if st.IsRunning {
		return "RUNNING"
	}
	return st.ServiceState
}
func (c *packetWebUIController) IsPaused() bool { return c.harness.IsPaused() }
func (c *packetWebUIController) Pause() error   { return c.harness.Pause() }
func (c *packetWebUIController) Resume() error  { return c.harness.Resume() }
func (c *packetWebUIController) LearnedDomains() []webui.LearnedDomainInfo {
	domains := c.harness.ListLearnedDomains()
	res := make([]webui.LearnedDomainInfo, len(domains))
	for i, d := range domains {
		res[i] = webui.LearnedDomainInfo{
			Domain:      d.Domain,
			Stage:       d.Stage,
			Strategy:    d.StrategyName(),
			FakeMode:    d.FakeMode,
			FakeTTL:     d.FakeTTL,
			SplitOffset: d.SplitOffset,
			DelayMS:     d.DelayMS,
		}
	}
	return res
}
func (c *packetWebUIController) Stats() webui.WebUIStats {
	r, s, q, fp, cand := c.harness.Stats()
	h, sp, inj, fb, se := c.harness.ExtendedStats()
	fi, ttl, badChk, _ := c.harness.FakeStats()
	dnsInt, dnsDoh, dnsFb := c.harness.DNSStats()
	retrans, esc, doms := c.harness.AutoLearnStats()
	shBlocks, flushes, p2Desync := c.harness.SinkholeStats()
	return webui.WebUIStats{
		PacketsRecv:                r,
		PacketsSent:                s,
		QUICDropped:                q,
		TCPFastPath:                fp,
		TCPCandidate:               cand,
		CandidateHandshakes:        h,
		PacketsSplit:               sp,
		OutOfOrderSegmentsInjected: inj,
		PassThroughFallbacks:       fb,
		SendErrors:                 se,
		FakePacketsInjected:        fi,
		FakeTTLCount:               ttl,
		FakeBadChecksumCount:       badChk,
		DNSQueriesIntercepted:      dnsInt,
		DNSQueriesResolvedDoH:      dnsDoh,
		DNSFallbacks:               dnsFb,
		RetransmissionsDetected:    retrans,
		StrategyEscalations:        esc,
		DomainsAutoLearned:         doms,
		SinkholeBlocks:             shBlocks,
		DNSFlushesTriggered:        flushes,
		Packet2Desynced:            p2Desync,
	}
}

// buildHarnessConfig maps application and packet configuration into divert.HarnessConfig.
// When InterceptDNS is enabled, it guarantees that a valid DoHResolver is initialized.
func buildHarnessConfig(cfg *config.Config, logger *slog.Logger, explicitOverrides bool) (divert.HarnessConfig, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	harnessCfg := divert.DefaultHarnessConfig()
	harnessCfg.Logger = logger
	harnessCfg.ExplicitOverrides = explicitOverrides
	harnessCfg.DropQUIC = cfg.Packet.DropQUICOrDefault()
	harnessCfg.DesyncHTTP = cfg.Packet.DesyncHTTPOrDefault()
	if cfg.Packet.SplitOffset != "" {
		harnessCfg.SplitOffset = cfg.Packet.SplitOffset
	}
	harnessCfg.InterPacketDelay = time.Duration(cfg.Packet.InterPacketDelayMS) * time.Millisecond
	harnessCfg.FakePacketMode = cfg.Packet.FakePacketMode
	if cfg.Packet.FakeTTL > 0 {
		harnessCfg.FakeTTL = uint8(cfg.Packet.FakeTTL)
	}
	if cfg.Packet.FakeSNI != "" {
		harnessCfg.FakeSNI = cfg.Packet.FakeSNI
	}
	harnessCfg.FakePacketDelay = time.Duration(cfg.Packet.FakeDelayMS) * time.Millisecond
	harnessCfg.DefaultProfile = cfg.DefaultProfile
	if strings.EqualFold(harnessCfg.DefaultProfile, "none") && len(cfg.DomainRules) == 0 {
		harnessCfg.DefaultProfile = "packet"
	}

	harnessCfg.InterceptDNS = cfg.Packet.InterceptDNSOrDefault()
	if harnessCfg.InterceptDNS {
		harnessCfg.Filter = divert.FilterOutboundWithDNS
		dohCfg := cfg.DoH
		dohCfg.Enabled = true
		if len(dohCfg.Endpoints) == 0 {
			dohCfg.Endpoints = config.DefaultConfig().DoH.Endpoints
		}
		resolver, err := dnsdoh.NewResolver(dohCfg, logger)
		if err != nil {
			return divert.HarnessConfig{}, fmt.Errorf("initialize DoH resolver for DNS interception: %w", err)
		}
		harnessCfg.DNSResolver = resolver
		harnessCfg.DoHResolver = resolver
	}

	harnessCfg.AutoLearn = cfg.Packet.AutoLearnOrDefault()
	harnessCfg.AutoLearnPath = cfg.Packet.AutoLearnPath
	dohEndpoints := cfg.DoH.Endpoints
	if len(dohEndpoints) == 0 {
		dohEndpoints = config.DefaultConfig().DoH.Endpoints
	}
	for _, ep := range dohEndpoints {
		if u, err := url.Parse(ep.URL); err == nil && u.Hostname() != "" {
			harnessCfg.DoHEndpoints = append(harnessCfg.DoHEndpoints, u.Hostname())
		} else if ep.URL != "" {
			harnessCfg.DoHEndpoints = append(harnessCfg.DoHEndpoints, ep.URL)
		}
	}

	if len(cfg.DomainRules) > 0 {
		matcher, err := config.NewDomainMatcher(cfg.DomainRules)
		if err != nil {
			return divert.HarnessConfig{}, fmt.Errorf("compile domain rules: %w", err)
		}
		harnessCfg.DomainMatcher = matcher
	}

	return harnessCfg, nil
}

func executeRunPacket(ctx context.Context, cfg *config.Config, logger *slog.Logger, webuiAddr string, explicitOverrides bool) error {
	elevated, err := divert.IsElevated()
	if err != nil {
		return fmt.Errorf("check process elevation: %w", err)
	}
	if !elevated {
		return errors.New("administrative privileges required to run in packet mode; please run dpibypass from an elevated command prompt (Run as Administrator)")
	}

	if !divert.IsAvailable() {
		return errors.New("WinDivert.dll not found; please ensure WinDivert.dll and WinDivert64.sys are placed in the same directory as dpibypass.exe or in system PATH")
	}

	harnessCfg, err := buildHarnessConfig(cfg, logger, explicitOverrides)
	if err != nil {
		return err
	}

	if harnessCfg.InterceptDNS {
		var dohResolver dnsdoh.Resolver
		if r, ok := harnessCfg.DoHResolver.(dnsdoh.Resolver); ok && r != nil {
			dohResolver = r
		} else {
			dohCfg := cfg.DoH
			dohCfg.Enabled = true
			if len(dohCfg.Endpoints) == 0 {
				dohCfg.Endpoints = config.DefaultConfig().DoH.Endpoints
			}
			if r, rErr := dnsdoh.NewResolver(dohCfg, logger); rErr == nil {
				dohResolver = r
			}
		}
		if syncErr := dnsdoh.SyncManagedHosts(ctx, dohResolver, logger); syncErr != nil {
			logger.Warn("failed to sync DoH IPs to Windows hosts file", "error", syncErr)
		} else {
			defer func() {
				if rmErr := dnsdoh.RemoveManagedHosts(); rmErr != nil {
					logger.Warn("failed to remove managed hosts block on shutdown", "error", rmErr)
				}
			}()
		}
	}

	harness := divert.NewHarness(harnessCfg)
	if err := harness.Start(); err != nil {
		return fmt.Errorf("start WinDivert harness: %w", err)
	}
	defer func() {
		_ = harness.Close()
	}()

	if harnessCfg.InterceptDNS {
		go func() {
			out, err := divert.FlushDNSCache()
			if err != nil {
				logger.Warn("failed to flush Windows DNS cache", "error", err)
			} else {
				logger.Info("flushed Windows DNS cache successfully", "output", strings.TrimSpace(string(out)))
			}
			time.Sleep(300 * time.Millisecond)
			prewarmDomains := []string{
				"discord.com",
				"updates.discord.com",
				"gateway.discord.gg",
				"cdn.discordapp.com",
				"media.discordapp.net",
				"status.discord.com",
				"dl.discordapp.net",
				"www.roblox.com",
			}
			for _, d := range prewarmDomains {
				if ctx.Err() != nil {
					return
				}
				lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, _ = net.DefaultResolver.LookupHost(lookupCtx, d)
				cancel()
			}
		}()
	}

	if webuiAddr != "" {
		ctrl := &packetWebUIController{harness: harness, cfg: cfg}
		webuiServer, err := webui.NewServer(webuiAddr, ctrl, logger)
		if err != nil {
			return fmt.Errorf("initialize webui: %w", err)
		}
		go func() {
			if err := webuiServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("webui server error", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = webuiServer.Shutdown(shutdownCtx)
		}()
	}

	logger.Info("packet interception engine started",
		"mode", "packet",
		"filter", harnessCfg.Filter,
		"drop_quic", harnessCfg.DropQUIC,
		"intercept_dns", harnessCfg.InterceptDNS,
		"desync_http", harnessCfg.DesyncHTTP,
		"fake_mode", harnessCfg.FakePacketMode,
		"fake_ttl", harnessCfg.FakeTTL,
		"split_offset", harnessCfg.SplitOffset,
		"inter_delay_ms", cfg.Packet.InterPacketDelayMS,
		"auto_learn", harnessCfg.AutoLearn,
	)

	fmt.Println("dpibypass packet engine running (press Ctrl+C to stop)...")

	runErr := harness.Run(ctx)

	printHarnessStatsSummary(harness)

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return fmt.Errorf("packet engine error: %w", runErr)
	}
	return nil
}

func printHarnessStatsSummary(harness *divert.Harness) {
	recv, sent, quicDrop, fastPath, candidate := harness.Stats()
	handshakes, split, injected, fallbacks, sendErrors := harness.ExtendedStats()
	fakeInjected, fakeTTL, fakeBadChksum, fakeSendErrors := harness.FakeStats()
	dnsIntercepted, dnsResolved, dnsFallbacks := harness.DNSStats()
	retrans, esc, doms := harness.AutoLearnStats()

	fmt.Println("\n=== WinDivert Packet Engine Summary ===")
	fmt.Printf("Total Packets Intercepted : %d\n", recv)
	fmt.Printf("Total Packets Transmitted   : %d\n", sent)
	fmt.Printf("TCP Fast-Path Pass-Through  : %d\n", fastPath)
	fmt.Printf("QUIC UDP/443 Dropped        : %d\n", quicDrop)
	fmt.Printf("DNS UDP/53 Intercepted      : %d (DoH Resolved: %d, Fallbacks: %d)\n", dnsIntercepted, dnsResolved, dnsFallbacks)
	fmt.Printf("TCP Candidate Packets       : %d\n", candidate)
	fmt.Printf("Candidate Handshakes Parsed : %d\n", handshakes)
	fmt.Printf("Synthetic Fake Packets Sent : %d (TTL: %d, BadChecksum: %d)\n", fakeInjected, fakeTTL, fakeBadChksum)
	fmt.Printf("Out-of-Order Segments Split : %d (Injected: %d)\n", split, injected)
	fmt.Printf("Pass-Through Fallbacks      : %d\n", fallbacks)
	if harness.IsAutoLearnEnabled() || retrans > 0 || esc > 0 || doms > 0 {
		fmt.Printf("Retransmissions Detected    : %d\n", retrans)
		fmt.Printf("Strategy Escalations        : %d\n", esc)
		fmt.Printf("Domains Auto-Learned        : %d\n", doms)
	}
	if sendErrors > 0 || fakeSendErrors > 0 {
		fmt.Printf("Send Errors Recorded        : %d\n", sendErrors+fakeSendErrors)
	}
}

func resolveBootstrapIPs(urlStr string) []string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return nil
	}
	switch strings.ToLower(host) {
	case "cloudflare-dns.com", "one.one.one.one":
		return []string{"1.1.1.1", "1.0.0.1"}
	case "dns.google":
		return []string{"8.8.8.8", "8.8.4.4"}
	case "dns.quad9.net":
		return []string{"9.9.9.9", "149.112.112.112"}
	default:
		return []string{"1.1.1.1", "8.8.8.8"}
	}
}

func executeCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass check --domain <domain> [--port <port>] [--config <path>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	domain := fs.String("domain", "", "target domain to check (required)")
	configPath := fs.String("config", "", "path to JSON configuration file (optional)")
	port := fs.Int("port", 443, "target port (default 443)")
	dohURL := fs.String("doh-url", "", "override or enable DoH resolver endpoint URL (e.g. https://cloudflare-dns.com/dns-query)")
	dohEnabled := fs.Bool("doh", false, "force enable built-in DoH resolver")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *domain == "" {
		return errors.New("--domain is required")
	}

	cfg, _, err := resolveConfig(*configPath)
	if err != nil {
		return fmt.Errorf("resolve configuration: %w", err)
	}

	if *dohURL != "" {
		cfg.DoH.Enabled = true
		cfg.DoH.Endpoints = []config.DoHEndpoint{{
			URL:          *dohURL,
			BootstrapIPs: resolveBootstrapIPs(*dohURL),
		}}
	} else if *dohEnabled {
		cfg.DoH.Enabled = true
	}

	matcher, err := config.NewDomainMatcher(cfg.DomainRules)
	if err != nil {
		return fmt.Errorf("compile domain rules: %w", err)
	}

	profileName := cfg.DefaultProfile
	matched := false
	if prof, ok := matcher.Match(*domain); ok {
		profileName = prof
		matched = true
	}

	profCfg, ok := cfg.Profiles[profileName]
	if !ok {
		if matched {
			return fmt.Errorf("domain rule for %q references profile %q which does not exist in configuration", *domain, profileName)
		}
		return fmt.Errorf("default_profile %q does not exist in configuration", profileName)
	}

	strat, err := strategy.FromProfile(profCfg)
	if err != nil {
		return fmt.Errorf("build strategy for profile %q: %w", profileName, err)
	}

	checkerCfg := diagnostics.DefaultCheckerConfig()
	if cfg.DoH.Enabled {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		res, err := dnsdoh.NewResolver(cfg.DoH, logger)
		if err != nil {
			return fmt.Errorf("initialize DoH resolver: %w", err)
		}
		checkerCfg.Resolver = res
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fmt.Printf("Checking target: %s:%d\n", *domain, *port)
	if matched {
		fmt.Printf("Domain rule matched: profile %q (type: %s)\n", profileName, profCfg.Type)
	} else {
		fmt.Printf("No domain rule matched; using default profile %q (type: %s)\n", profileName, profCfg.Type)
	}
	fmt.Println("Probing with GET / ...")

	result := diagnostics.RunCheck(ctx, *domain, *port, strat, checkerCfg)

	fmt.Println()
	fmt.Printf("Outcome        : %s\n", result.Outcome.String())
	if len(result.ResolvedIPs) > 0 {
		fmt.Printf("Resolved IP(s) : %s\n", strings.Join(result.ResolvedIPs, ", "))
	}
	if result.HTTPStatusCode > 0 {
		fmt.Printf("HTTP Status    : %d\n", result.HTTPStatusCode)
	}
	if result.FailureReason != "" {
		fmt.Printf("Detail         : %s\n", result.FailureReason)
	}
	fmt.Println("Stage Latencies:")
	if result.DNSDuration > 0 {
		fmt.Printf("  DNS Lookup   : %v\n", result.DNSDuration)
	}
	if result.TCPDuration > 0 {
		fmt.Printf("  TCP Connect  : %v\n", result.TCPDuration)
	}
	if result.TLSDuration > 0 {
		fmt.Printf("  TLS Handshake: %v\n", result.TLSDuration)
	}
	if result.HTTPDuration > 0 {
		fmt.Printf("  HTTP Probe   : %v\n", result.HTTPDuration)
	}
	fmt.Printf("  Total Time   : %v\n", result.TotalDuration)
	fmt.Println()

	if result.Outcome == diagnostics.OutcomeHTTPRestricted {
		fmt.Println("Note: Observed HTTP status indicates access restriction; this is consistent")
		fmt.Println("      with blocking or access control, not proof of DPI interference.")
	}
	fmt.Println("Notice: Diagnostics measure observed connectivity and protocol outcomes;")
	fmt.Println("        they do not independently establish DPI interference or guarantee")
	fmt.Println("        that a strategy will bypass a real ISP's DPI.")

	if !result.IsSuccess() && result.Outcome != diagnostics.OutcomeHTTPRestricted {
		return fmt.Errorf("check finished with outcome %s", result.Outcome.String())
	}
	return nil
}

func executeTune(args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass tune --domains <d1,d2> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	domainsStr := fs.String("domains", "", "comma-separated list of domains to evaluate (required)")
	configPath := fs.String("config", "", "path to JSON configuration file (optional)")
	modeFlag := fs.String("mode", "", "tuning mode: 'proxy' (Phase 1 strategy tuning) or 'packet' (WinDivert auto-TTL calibration)")
	profilesStr := fs.String("profiles", "", "comma-separated list of candidate profiles to test (optional)")
	trials := fs.Int("trials", 3, "number of sequential trials per profile (default 3)")
	delayMS := fs.Int("delay-ms", 500, "delay in milliseconds between trials (default 500)")
	apply := fs.Bool("apply", false, "safely apply conclusive recommendation to configuration")
	dohURL := fs.String("doh-url", "", "override or enable DoH resolver endpoint URL (e.g. https://cloudflare-dns.com/dns-query)")
	dohEnabled := fs.Bool("doh", false, "force enable built-in DoH resolver")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *domainsStr == "" {
		return errors.New("--domains is required")
	}

	if *trials <= 0 || *trials > tuner.MaxTrials {
		return fmt.Errorf("--trials must be between 1 and %d", tuner.MaxTrials)
	}
	if *delayMS < 0 || *delayMS > 10000 {
		return errors.New("--delay-ms must be between 0 and 10000 ms")
	}

	cfg, loadedPath, err := resolveConfig(*configPath)
	if err != nil {
		return fmt.Errorf("resolve configuration: %w", err)
	}

	if *dohURL != "" {
		cfg.DoH.Enabled = true
		cfg.DoH.Endpoints = []config.DoHEndpoint{{
			URL:          *dohURL,
			BootstrapIPs: resolveBootstrapIPs(*dohURL),
		}}
	} else if *dohEnabled {
		cfg.DoH.Enabled = true
	}

	if *apply && loadedPath == "" {
		return errors.New("cannot use --apply with default in-memory configuration; please specify --config <path>")
	}

	rawDomains := strings.Split(*domainsStr, ",")
	var domains []string
	for _, d := range rawDomains {
		norm := config.NormalizeDomain(d)
		if norm != "" {
			domains = append(domains, norm)
		}
	}
	if len(domains) == 0 {
		return errors.New("no valid domains specified in --domains")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if strings.EqualFold(*modeFlag, "packet") || (*modeFlag == "" && cfg.Mode == config.ModePacket) {
		return executeTunePacket(ctx, domains, *trials, *delayMS, *apply, loadedPath, cfg)
	}

	var candidateProfiles []string
	if *profilesStr != "" {
		for _, p := range strings.Split(*profilesStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" && p != "none" {
				if _, exists := cfg.Profiles[p]; !exists {
					return fmt.Errorf("specified profile %q does not exist in configuration", p)
				}
				candidateProfiles = append(candidateProfiles, p)
			}
		}
	}

	checkerCfg := diagnostics.DefaultCheckerConfig()
	if cfg.DoH.Enabled {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		res, err := dnsdoh.NewResolver(cfg.DoH, logger)
		if err != nil {
			return fmt.Errorf("initialize DoH resolver: %w", err)
		}
		checkerCfg.Resolver = res
	}

	tunerCfg := tuner.TunerConfig{
		Trials:        *trials,
		InterDelay:    time.Duration(*delayMS) * time.Millisecond,
		Port:          diagnostics.DefaultPort,
		CheckerConfig: checkerCfg,
		Profiles:      cfg.Profiles,
	}

	fmt.Printf("Starting strategy tuning for %d target(s) (trials: %d, delay: %dms)...\n\n", len(domains), *trials, *delayMS)

	var results []tuner.DomainTuneResult
	for _, domain := range domains {
		fmt.Printf("Evaluating %s ...\n", domain)
		res := tuner.TuneDomain(ctx, domain, candidateProfiles, tunerCfg)
		results = append(results, res)
	}

	fmt.Println()
	fmt.Print(tuner.FormatReport(results))

	if *apply {
		fmt.Println("\nAttempting safe configuration apply...")
		applyRes, err := tuner.SafeApplyRecommendation(loadedPath, results)
		if err != nil {
			return fmt.Errorf("apply configuration failed: %w", err)
		}
		fmt.Printf("Configuration successfully updated: %s\n", applyRes.ConfigPath)
		fmt.Printf("Backup preserved at: %s\n", applyRes.BackupPath)
		if len(applyRes.Updated) > 0 {
			fmt.Printf("Updated domain rules : %s\n", strings.Join(applyRes.Updated, ", "))
		}
		if len(applyRes.Added) > 0 {
			fmt.Printf("Added domain rules   : %s\n", strings.Join(applyRes.Added, ", "))
		}
	}

	return nil
}

func executeTunePacket(ctx context.Context, domains []string, trials int, delayMS int, apply bool, loadedPath string, cfg *config.Config) error {
	elevated, err := divert.IsElevated()
	if err != nil {
		return fmt.Errorf("check process elevation: %w", err)
	}
	if !elevated {
		return errors.New("administrative privileges required to tune in packet mode; please run dpibypass from an elevated command prompt (Run as Administrator)")
	}

	if !divert.IsAvailable() {
		return errors.New("WinDivert.dll not found; please ensure WinDivert.dll and WinDivert64.sys are present in current directory or PATH")
	}

	var dohResolver *dnsdoh.DoHResolver
	if cfg.DoH.Enabled {
		nullLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
		dohResolver, _ = dnsdoh.NewResolver(cfg.DoH, nullLogger)
	} else {
		// Initialize fallback DoH resolver for DNS poisoning detection and probe calibration
		fallbackCfg := config.DefaultConfig().DoH
		fallbackCfg.Enabled = true
		nullLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
		dohResolver, _ = dnsdoh.NewResolver(fallbackCfg, nullLogger)
	}

	fmt.Printf("Starting WinDivert packet Auto-TTL tuning for %d target(s) (trials: %d, delay: %dms)...\n\n", len(domains), trials, delayMS)

	candidateTTLs := tuner.DefaultCandidateTTLs
	var results []tuner.PacketTuneResult

	for _, domain := range domains {
		fmt.Printf("Evaluating %s ...\n", domain)

		dnsCheck := tuner.CheckDNSPoisoning(ctx, domain, dohResolver)
		if dnsCheck.PoisoningRisk {
			fmt.Printf("  [WARNING] %s\n", dnsCheck.Warning)
			fmt.Println("  [INFO] Poisoned/blocked System DNS detected; probe will use secure DoH to test packet bypass against the real target IP.")
		}

		probeFn := func(probeCtx context.Context, d string, port int, ttl uint8) (bool, time.Duration, error) {
			harnessCfg := divert.DefaultHarnessConfig()
			harnessCfg.FakePacketMode = "ttl"
			harnessCfg.FakeTTL = ttl
			harnessCfg.SplitOffset = "sni-mid"
			harnessCfg.TargetDomains = []string{d}
			harnessCfg.DefaultProfile = "packet"
			harnessCfg.DesyncHTTP = true

			harness := divert.NewHarness(harnessCfg)
			if err := harness.Start(); err != nil {
				return false, 0, err
			}
			defer func() { _ = harness.Close() }()

			hCtx, cancelH := context.WithCancel(probeCtx)
			defer cancelH()

			go func() {
				_ = harness.Run(hCtx)
			}()

			time.Sleep(30 * time.Millisecond)

			chkCfg := diagnostics.DefaultCheckerConfig()
			if (cfg.DoH.Enabled || dnsCheck.PoisoningRisk) && dohResolver != nil {
				chkCfg.Resolver = dohResolver
			}
			res := diagnostics.RunCheck(probeCtx, d, port, strategy.NewNoneStrategy(), chkCfg)
			return res.IsSuccess(), res.TotalDuration, nil
		}

		res := tuner.TunePacketDomain(ctx, domain, 443, candidateTTLs, trials, time.Duration(delayMS)*time.Millisecond, dnsCheck, probeFn)
		results = append(results, res)
	}

	fmt.Println()
	fmt.Print(tuner.FormatPacketReport(results))

	if apply {
		var chosenTTL uint8
		for _, r := range results {
			if r.IsConclusive && r.RecommendedTTL > 0 {
				if chosenTTL == 0 || r.RecommendedTTL > chosenTTL {
					chosenTTL = r.RecommendedTTL
				}
			}
		}

		if chosenTTL > 0 && loadedPath != "" {
			fmt.Println("\nAttempting safe configuration apply for packet mode...")
			cfg.Packet.FakeTTL = int(chosenTTL)
			cfg.Packet.FakePacketMode = "ttl"
			cfg.Packet.SplitOffset = "sni-mid"

			backupPath, err := tuner.CreateAtomicBackup(loadedPath)
			if err != nil {
				return fmt.Errorf("create config backup: %w", err)
			}
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return fmt.Errorf("serialize config: %w", err)
			}
			if err := os.WriteFile(loadedPath, append(data, '\n'), 0644); err != nil {
				return fmt.Errorf("write updated config: %w", err)
			}
			fmt.Printf("Configuration successfully updated: %s (fake_ttl: %d)\n", loadedPath, chosenTTL)
			fmt.Printf("Backup preserved at: %s\n", backupPath)
		} else if chosenTTL == 0 {
			fmt.Println("\nConfiguration not modified: Tuning results were inconclusive across tested domains.")
		}
	}

	return nil
}

func executeConfig(args []string) error {
	if len(args) == 0 {
		printConfigUsage()
		return errors.New("subcommand required for 'config' (e.g. 'validate')")
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printConfigUsage()
		return nil
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "validate":
		fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: dpibypass config validate [--config <path>]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Options:")
			fs.PrintDefaults()
		}
		configPath := fs.String("config", "", "path to JSON configuration file to validate")
		if err := fs.Parse(subArgs); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}

		targetPath := *configPath
		if targetPath == "" {
			if _, err := os.Stat("config.json"); err == nil {
				targetPath = "config.json"
			}
		}

		if targetPath == "" {
			cfg := config.DefaultConfig()
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("default configuration is invalid: %w", err)
			}
			fmt.Println("Default configuration is valid (loopback: 127.0.0.1:1080).")
			return nil
		}

		cfg, err := config.Load(targetPath)
		if err != nil {
			return fmt.Errorf("configuration %q failed validation: %w", targetPath, err)
		}
		fmt.Printf("Configuration %q is valid (version %d, listen %s, default_profile %q).\n",
			targetPath, cfg.Version, cfg.Listen, cfg.DefaultProfile)
		return nil

	default:
		printConfigUsage()
		return fmt.Errorf("unknown config subcommand %q; expected 'validate'", subcmd)
	}
}

func executeSysproxy(args []string) error {
	if len(args) == 0 {
		printSysproxyUsage()
		return errors.New("subcommand required for 'sysproxy' ('on', 'off', 'status', or 'restore')")
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printSysproxyUsage()
		return nil
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "on":
		return executeSysproxyOn(subArgs)
	case "off":
		return executeSysproxyOff(subArgs)
	case "status":
		return executeSysproxyStatus(subArgs)
	case "restore":
		return executeSysproxyRestore(subArgs)
	default:
		printSysproxyUsage()
		return fmt.Errorf("unknown sysproxy subcommand %q; expected 'on', 'off', 'status', or 'restore'", subcmd)
	}
}

func executeSysproxyOn(args []string) error {
	fs := flag.NewFlagSet("sysproxy on", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass sysproxy on [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to JSON configuration file (optional)")
	addrFlag := fs.String("addr", "", "proxy address and port, e.g. 127.0.0.1:1080 (optional; derived from config if omitted)")
	backupPathFlag := fs.String("backup", "", "path to backup file (optional; defaults to %LOCALAPPDATA%\\dpibypass\\sysproxy_backup.json)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	targetAddr := *addrFlag
	if targetAddr == "" {
		cfg, _, err := resolveConfig(*configPath)
		if err != nil {
			return fmt.Errorf("resolve configuration for proxy address: %w", err)
		}
		targetAddr = cfg.Listen
	}

	backupPath := *backupPathFlag
	if backupPath == "" {
		resolved, err := sysproxy.DefaultBackupPath()
		if err != nil {
			return err
		}
		backupPath = resolved
	}

	store := sysproxy.NewWindowsStore("")
	mgr := sysproxy.NewManager(store)

	res, err := mgr.Enable(targetAddr, backupPath)
	if err != nil {
		return fmt.Errorf("enable system proxy: %w", err)
	}

	fmt.Println("Windows system proxy enabled successfully:")
	fmt.Printf("  Configured server : %s\n", res.ConfiguredServer)
	fmt.Printf("  Backup preserved  : %s\n", res.BackupPath)
	fmt.Println("  Scope             : HTTP and HTTPS proxy traffic (per-user WinINet; WinHTTP only when explicitly configured)")
	if res.NotificationWarning != "" {
		fmt.Printf("\nWarning: %s\n", res.NotificationWarning)
	}
	fmt.Println("\nNote: Applications with independent network configurations (e.g. Firefox custom proxy, CLI tools requiring env vars, Discord UDP voice, and games) will not route through Windows system proxy settings.")
	return nil
}

func executeSysproxyOff(args []string) error {
	fs := flag.NewFlagSet("sysproxy off", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass sysproxy off [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	backupPathFlag := fs.String("backup", "", "path to backup file (optional; defaults to %LOCALAPPDATA%\\dpibypass\\sysproxy_backup.json)")
	forceFlag := fs.Bool("force", false, "restore original backup even if external modification was detected")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	backupPath := *backupPathFlag
	if backupPath == "" {
		resolved, err := sysproxy.DefaultBackupPath()
		if err != nil {
			return err
		}
		backupPath = resolved
	}

	store := sysproxy.NewWindowsStore("")
	mgr := sysproxy.NewManager(store)

	res, err := mgr.Disable(backupPath, *forceFlag)
	if err != nil {
		if errors.Is(err, sysproxy.ErrExternalModification) {
			return fmt.Errorf("%w\nRun 'dpibypass sysproxy status' to inspect current settings, or use '--force' to restore the original backup anyway", err)
		}
		if errors.Is(err, sysproxy.ErrNoBackupFound) || errors.Is(err, sysproxy.ErrCorruptBackup) {
			fmt.Fprintf(os.Stderr, "Error: exact restoration is impossible: %v\n\n", err)
			fmt.Fprintln(os.Stderr, "Safe manual recovery guidance:")
			fmt.Fprintln(os.Stderr, "  1. Open Windows Settings -> Network & internet -> Proxy")
			fmt.Fprintln(os.Stderr, "  2. Turn off 'Use a proxy server'")
			fmt.Fprintln(os.Stderr, "  Alternatively, run in PowerShell:")
			fmt.Fprintln(os.Stderr, "    Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0")
			return errors.New("restoration refused: missing or invalid recovery data")
		}
		return fmt.Errorf("disable system proxy: %w", err)
	}

	if res.AlreadyRestored {
		fmt.Println("Windows system proxy was already at original settings.")
		fmt.Printf("  Backup retired    : %s\n", res.BackupPath)
		return nil
	}

	fmt.Println("Windows system proxy disabled successfully:")
	fmt.Println("  Restoration status : complete (verified in registry)")
	if res.Forced {
		fmt.Println("  Mode               : forced restoration (bypassed external drift)")
	}
	fmt.Printf("  Backup retired     : %s\n", res.BackupPath)
	if res.NotificationWarning != "" {
		fmt.Printf("\nWarning: %s\n", res.NotificationWarning)
	}
	return nil
}

func executeSysproxyRestore(args []string) error {
	fs := flag.NewFlagSet("sysproxy restore", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass sysproxy restore [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	backupPathFlag := fs.String("backup", "", "path to backup file (optional; defaults to %LOCALAPPDATA%\\dpibypass\\sysproxy_backup.json)")
	forceFlag := fs.Bool("force", false, "restore original backup even if external modification was detected")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	backupPath := *backupPathFlag
	if backupPath == "" {
		resolved, err := sysproxy.DefaultBackupPath()
		if err != nil {
			return err
		}
		backupPath = resolved
	}

	store := sysproxy.NewWindowsStore("")
	mgr := sysproxy.NewManager(store)

	res, err := mgr.Restore(backupPath, *forceFlag)
	if err != nil {
		if errors.Is(err, sysproxy.ErrExternalModification) {
			return fmt.Errorf("%w\nRun 'dpibypass sysproxy status' to inspect current settings, or use '--force' to restore the original backup anyway", err)
		}
		if errors.Is(err, sysproxy.ErrNoBackupFound) || errors.Is(err, sysproxy.ErrCorruptBackup) {
			fmt.Fprintf(os.Stderr, "Error: exact restoration is impossible: %v\n\n", err)
			fmt.Fprintln(os.Stderr, "Safe manual recovery guidance:")
			fmt.Fprintln(os.Stderr, "  1. Open Windows Settings -> Network & internet -> Proxy")
			fmt.Fprintln(os.Stderr, "  2. Turn off 'Use a proxy server'")
			fmt.Fprintln(os.Stderr, "  Alternatively, run in PowerShell:")
			fmt.Fprintln(os.Stderr, "    Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0")
			return errors.New("restoration refused: missing or invalid recovery data")
		}
		return fmt.Errorf("restore system proxy: %w", err)
	}

	if res.AlreadyRestored {
		fmt.Println("Windows system proxy was already at original settings.")
		fmt.Printf("  Backup retired    : %s\n", res.BackupPath)
		return nil
	}

	fmt.Println("Windows system proxy restored successfully:")
	fmt.Println("  Restoration status : complete (verified in registry)")
	if res.Forced {
		fmt.Println("  Mode               : forced restoration (bypassed external drift)")
	}
	fmt.Printf("  Backup retired     : %s\n", res.BackupPath)
	if res.NotificationWarning != "" {
		fmt.Printf("\nWarning: %s\n", res.NotificationWarning)
	}
	return nil
}

func executeSysproxyStatus(args []string) error {
	fs := flag.NewFlagSet("sysproxy status", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass sysproxy status [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to JSON configuration file (optional; to check listener reachability)")
	addrFlag := fs.String("addr", "", "proxy address to check reachability (optional)")
	backupPathFlag := fs.String("backup", "", "path to backup file (optional; defaults to %LOCALAPPDATA%\\dpibypass\\sysproxy_backup.json)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	targetAddr := *addrFlag
	if targetAddr == "" {
		if cfg, _, err := resolveConfig(*configPath); err == nil && cfg != nil {
			targetAddr = cfg.Listen
		}
	}

	backupPath := *backupPathFlag
	if backupPath == "" {
		if resolved, err := sysproxy.DefaultBackupPath(); err == nil {
			backupPath = resolved
		}
	}

	store := sysproxy.NewWindowsStore("")
	mgr := sysproxy.NewManager(store)

	status, err := mgr.Status(backupPath, targetAddr)
	if err != nil {
		return fmt.Errorf("query sysproxy status: %w", err)
	}

	fmt.Println("=== Windows Internet Settings Proxy Status ===")
	var proxyEnableStr = "(missing)"
	if pe, ok := status.CurrentSettings[sysproxy.KeyProxyEnable]; ok && pe.Exists {
		dw, _ := sysproxy.DecodeDWORD(pe.Data)
		proxyEnableStr = fmt.Sprintf("%d", dw)
	}
	var proxyServerStr = "(missing)"
	if ps, ok := status.CurrentSettings[sysproxy.KeyProxyServer]; ok && ps.Exists {
		s, _ := sysproxy.DecodeString(ps.Data)
		proxyServerStr = s
	}

	fmt.Printf("ProxyEnable          : %s\n", proxyEnableStr)
	fmt.Printf("ProxyServer          : %s\n", proxyServerStr)
	if status.ProxyOverride != "" {
		fmt.Printf("ProxyOverride        : %s\n", status.ProxyOverride)
	}
	if status.AutoConfigURL != "" {
		fmt.Printf("AutoConfigURL (PAC)  : %s\n", status.AutoConfigURL)
	}

	fmt.Println()
	fmt.Printf("State                : %s\n", status.State)
	fmt.Println("Scope                : per-user WinINet (WinHTTP only when explicitly configured)")
	if status.ConfiguredListener != "" {
		reachStr := "unreachable"
		if status.ListenerReachable {
			reachStr = "reachable"
		}
		fmt.Printf("Listener (%s) : %s\n", status.ConfiguredListener, reachStr)
	}

	fmt.Println()
	fmt.Printf("Backup Path          : %s\n", status.BackupPath)
	if status.Backup != nil {
		fmt.Printf("Backup Timestamp     : %s\n", status.Backup.Timestamp.Format(time.RFC3339))
		fmt.Printf("Backup Applied Target: %s\n", status.Backup.ConfiguredServer)
	}

	if len(status.DriftDetails) > 0 {
		fmt.Println("\nExternal Drift Detected:")
		for _, d := range status.DriftDetails {
			fmt.Printf("  - %s\n", d)
		}
	}

	return nil
}

func executeRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dpibypass recover [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Inspect and safely recover from crashes or abnormal termination, restoring")
		fmt.Fprintln(os.Stderr, "Windows system proxy settings and verifying/cleaning WinDivert driver state.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}
	checkOnlyFlag := fs.Bool("check-only", false, "inspect and report status without applying recovery modifications")
	statusFlag := fs.Bool("status", false, "alias for --check-only")
	forceFlag := fs.Bool("force", false, "force restoration of proxy settings even if external drift is detected")
	backupPathFlag := fs.String("backup", "", "path to proxy backup file (optional; defaults to %LOCALAPPDATA%\\dpibypass\\sysproxy_backup.json)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	checkOnly := *checkOnlyFlag || *statusFlag

	fmt.Println("=== dpibypass Unified Crash Recovery & Status ===")

	// 1. Inspect & Recover Windows System Proxy
	fmt.Println("\n[1/2] Windows Internet Settings (System Proxy):")
	backupPath := *backupPathFlag
	if backupPath == "" {
		if resolved, err := sysproxy.DefaultBackupPath(); err == nil {
			backupPath = resolved
		}
	}

	store := sysproxy.NewWindowsStore("")
	mgr := sysproxy.NewManager(store)
	status, err := mgr.Status(backupPath, "")
	if err != nil {
		fmt.Printf("  Status query error: %v\n", err)
	} else {
		var peStr = "0 (disabled)"
		if pe, ok := status.CurrentSettings[sysproxy.KeyProxyEnable]; ok && pe.Exists {
			dw, _ := sysproxy.DecodeDWORD(pe.Data)
			if dw != 0 {
				peStr = "1 (ENABLED)"
			}
		}
		var psStr = "(none)"
		if ps, ok := status.CurrentSettings[sysproxy.KeyProxyServer]; ok && ps.Exists {
			s, _ := sysproxy.DecodeString(ps.Data)
			if s != "" {
				psStr = s
			}
		}

		fmt.Printf("  Proxy State     : %s\n", status.State)
		fmt.Printf("  ProxyEnable     : %s\n", peStr)
		fmt.Printf("  ProxyServer     : %s\n", psStr)
		if status.Backup != nil {
			fmt.Printf("  Backup File     : Present (%s, target: %s)\n", status.BackupPath, status.Backup.ConfiguredServer)
		} else {
			fmt.Println("  Backup File     : None")
		}

		if len(status.DriftDetails) > 0 {
			fmt.Println("  Drift Warning   : External changes detected")
			for _, d := range status.DriftDetails {
				fmt.Printf("    - %s\n", d)
			}
		}

		if status.State != sysproxy.StateInactiveClean {
			if checkOnly {
				fmt.Println("  Action          : Lingering proxy settings detected (run 'dpibypass recover' without --status to restore)")
			} else {
				fmt.Println("  Action          : Attempting safe proxy restoration...")
				res, restErr := mgr.Restore(backupPath, *forceFlag)
				if restErr != nil {
					fmt.Printf("  Restoration failed: %v\n", restErr)
					if errors.Is(restErr, sysproxy.ErrExternalModification) {
						fmt.Println("  Hint: Use --force to restore the original backup despite external drift.")
					}
				} else if res.AlreadyRestored {
					fmt.Println("  Restoration     : Proxy was already restored.")
				} else {
					fmt.Println("  Restoration     : SUCCESS (system proxy restored to pre-activation state)")
				}
			}
		} else {
			fmt.Println("  Action          : System proxy is clean. No restoration needed.")
		}
	}

	// 2. Inspect & Clean WinDivert Driver State
	fmt.Println("\n[2/2] WinDivert Kernel Driver & Service State:")
	driverSt := divert.QueryDriverStatus()
	fmt.Printf("  Platform Support : %v\n", driverSt.Supported)
	fmt.Printf("  Admin Elevation  : %v\n", driverSt.Elevated)
	fmt.Printf("  WinDivert.dll    : %v\n", driverSt.DLLAvailable)
	fmt.Printf("  Service Name     : %s\n", driverSt.ServiceName)
	fmt.Printf("  Service State    : %s\n", driverSt.ServiceState)

	if driverSt.IsRunning {
		if checkOnly {
			fmt.Println("  Action           : Service is currently RUNNING (run 'dpibypass recover' as Administrator to stop)")
		} else {
			fmt.Println("  Action           : Attempting to stop lingering WinDivert service...")
			if !driverSt.Elevated {
				fmt.Println("  Notice           : Administrator privileges required to stop driver service. Run in elevated shell.")
			} else {
				if stopErr := divert.StopDriverService(); stopErr != nil {
					fmt.Printf("  Stop failed      : %v\n", stopErr)
				} else {
					fmt.Println("  Service Stop     : SUCCESS (WinDivert driver service stopped cleanly)")
				}
			}
		}
	} else {
		fmt.Println("  Action           : Driver service is clean. No action needed.")
	}

	if !checkOnly {
		if rmErr := dnsdoh.RemoveManagedHosts(); rmErr != nil {
			fmt.Printf("  Hosts Cleanup    : Warning: %v\n", rmErr)
		} else {
			fmt.Println("  Hosts Cleanup    : Clean (dpibypass managed hosts entries removed)")
		}
	}

	fmt.Println("\nRecovery inspection complete.")
	return nil
}

func printConfigUsage() {
	fmt.Println("Usage: dpibypass config <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  validate [--config <path>]   Validate configuration file syntax, bounds, and loopback safety")
}

func printSysproxyUsage() {
	fmt.Println("Usage: dpibypass sysproxy <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  on [--addr <addr>] [--backup <path>]   Enable Windows system proxy for HTTP/HTTPS")
	fmt.Println("  off [--force] [--backup <path>]        Disable Windows system proxy and restore settings")
	fmt.Println("  status [--backup <path>]               Display Windows proxy and backup status")
	fmt.Println("  restore [--force] [--backup <path>]    Recover saved proxy settings after crash")
}

func printUsage() {
	fmt.Println("Usage: dpibypass <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run [--mode proxy|packet] [--config <path>]   Start the bypass engine (proxy or WinDivert packet mode)")
	fmt.Println("  check --domain <domain> [--port <port>]       Diagnose connectivity to target domain")
	fmt.Println("  tune --domains <d1,d2> [--apply]              Evaluate and tune candidate bypass strategies")
	fmt.Println("  config validate [--config <path>]             Validate configuration file syntax and bounds")
	fmt.Println("  recover [--check-only] [--force]              Unified crash recovery for proxy settings and driver state")
	fmt.Println("  sysproxy on [--addr <addr>] [--backup <path>] Enable Windows system proxy for HTTP/HTTPS")
	fmt.Println("  sysproxy off [--force] [--backup <path>]      Disable Windows system proxy and restore settings")
	fmt.Println("  sysproxy status [--backup <path>]             Display Windows proxy and backup status")
	fmt.Println("  sysproxy restore [--force] [--backup <path>]  Recover saved proxy settings after crash")
	fmt.Println("  version                                       Print dpibypass version")
	fmt.Println("  help                                          Show command usage")
}

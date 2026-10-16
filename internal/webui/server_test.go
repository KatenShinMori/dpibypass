package webui

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockEngineController struct {
	mode        string
	strategy    string
	driverState string
	paused      bool
	stats       WebUIStats
	learned     []LearnedDomainInfo
	pauseErr    error
	resumeErr   error
}

func (m *mockEngineController) Mode() string                        { return m.mode }
func (m *mockEngineController) Strategy() string                    { return m.strategy }
func (m *mockEngineController) DriverState() string                 { return m.driverState }
func (m *mockEngineController) IsPaused() bool                      { return m.paused }
func (m *mockEngineController) LearnedDomains() []LearnedDomainInfo { return m.learned }
func (m *mockEngineController) Pause() error {
	if m.pauseErr != nil {
		return m.pauseErr
	}
	m.paused = true
	m.driverState = "STOPPED"
	return nil
}
func (m *mockEngineController) Resume() error {
	if m.resumeErr != nil {
		return m.resumeErr
	}
	m.paused = false
	m.driverState = "RUNNING"
	return nil
}
func (m *mockEngineController) Stats() WebUIStats { return m.stats }

func TestNewServer_LoopbackEnforcement(t *testing.T) {
	ctrl := &mockEngineController{mode: "packet", driverState: "RUNNING"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Non-loopback addresses must be rejected
	invalidAddrs := []string{
		"0.0.0.0:8787",
		"192.168.1.100:8787",
		"10.0.0.1:8787",
		":8787",
	}

	for _, addr := range invalidAddrs {
		_, err := NewServer(addr, ctrl, logger)
		if err == nil {
			t.Errorf("NewServer with addr %q should fail loopback check, got nil", addr)
		}
	}

	// Loopback address must be accepted
	validAddrs := []string{
		"127.0.0.1:8787",
		"127.0.0.1:0",
		"localhost:8787",
	}

	for _, addr := range validAddrs {
		s, err := NewServer(addr, ctrl, logger)
		if err != nil {
			t.Errorf("NewServer with addr %q failed unexpectedly: %v", addr, err)
		}
		if s == nil {
			t.Errorf("expected non-nil server for addr %q", addr)
		}
	}
}

func TestWebUI_HostHeaderDNSRebindingProtection(t *testing.T) {
	ctrl := &mockEngineController{
		mode:        "packet",
		strategy:    "TTL 5 + OOO Split",
		driverState: "RUNNING",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer("127.0.0.1:8787", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// 1. Malicious Host headers (DNS rebinding)
	maliciousHosts := []string{
		"evil.com",
		"attacker.org:8787",
		"192.168.1.1:8787",
		"example.com",
	}

	for _, h := range maliciousHosts {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/stats", nil)
		req.Host = h
		rr := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for malicious Host %q, got %d", h, rr.Code)
		}
	}

	// 2. Valid loopback Host headers
	validHosts := []string{
		"127.0.0.1:8787",
		"127.0.0.1",
		"localhost:8787",
		"localhost",
	}

	for _, h := range validHosts {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/stats", nil)
		req.Host = h
		rr := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for valid Host %q, got %d", h, rr.Code)
		}
	}
}

func TestWebUI_CSRFProtection(t *testing.T) {
	ctrl := &mockEngineController{mode: "packet", driverState: "RUNNING"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer("127.0.0.1:8787", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// 1. Cross-origin POST with external Origin header
	reqBadOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/pause", nil)
	reqBadOrigin.Host = "127.0.0.1:8787"
	reqBadOrigin.Header.Set("Origin", "http://evil.com")
	rrBadOrigin := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rrBadOrigin, reqBadOrigin)

	if rrBadOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external Origin, got %d", rrBadOrigin.Code)
	}

	// 2. Cross-origin POST with external Referer header
	reqBadReferer := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/pause", nil)
	reqBadReferer.Host = "127.0.0.1:8787"
	reqBadReferer.Header.Set("Referer", "http://malicious.org/csrf.html")
	rrBadReferer := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rrBadReferer, reqBadReferer)

	if rrBadReferer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external Referer, got %d", rrBadReferer.Code)
	}

	// 3. Sec-Fetch-Site cross-site header
	reqCrossSite := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/pause", nil)
	reqCrossSite.Host = "127.0.0.1:8787"
	reqCrossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	rrCrossSite := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rrCrossSite, reqCrossSite)

	if rrCrossSite.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Sec-Fetch-Site: cross-site, got %d", rrCrossSite.Code)
	}

	// 4. Legitimate loopback Origin POST
	reqGoodOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/pause", nil)
	reqGoodOrigin.Host = "127.0.0.1:8787"
	reqGoodOrigin.Header.Set("Origin", "http://127.0.0.1:8787")
	rrGoodOrigin := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rrGoodOrigin, reqGoodOrigin)

	if rrGoodOrigin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for loopback Origin, got %d", rrGoodOrigin.Code)
	}
}

func TestWebUI_StatsEndpointSerialization(t *testing.T) {
	ctrl := &mockEngineController{
		mode:        "packet",
		strategy:    "TTL 5 + OOO Split (sni-mid)",
		driverState: "RUNNING",
		paused:      false,
		stats: WebUIStats{
			PacketsRecv:                1500,
			TCPFastPath:                1200,
			QUICDropped:                50,
			CandidateHandshakes:        250,
			FakePacketsInjected:        250,
			PacketsSplit:               250,
			OutOfOrderSegmentsInjected: 500,
			PassThroughFallbacks:       0,
			SendErrors:                 0,
			RetransmissionsDetected:    7,
			StrategyEscalations:        5,
			DomainsAutoLearned:         2,
		},
		learned: []LearnedDomainInfo{
			{
				Domain:      "updates.discord.com",
				Stage:       2,
				Strategy:    "Stage 2 (TTL 6 + sni-end + 2ms delay)",
				FakeMode:    "ttl",
				FakeTTL:     6,
				SplitOffset: "sni-end",
				DelayMS:     2,
			},
			{
				Domain:      "roblox.com",
				Stage:       1,
				Strategy:    "Stage 1 (TTL 3 + sni-start)",
				FakeMode:    "ttl",
				FakeTTL:     3,
				SplitOffset: "sni-start",
				DelayMS:     0,
			},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer("127.0.0.1:8787", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/stats", nil)
	req.Host = "127.0.0.1:8787"
	rr := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("stats status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var resp statsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode stats JSON: %v", err)
	}

	if resp.Mode != "packet" {
		t.Errorf("Mode = %q, want packet", resp.Mode)
	}
	if resp.DriverState != "RUNNING" {
		t.Errorf("DriverState = %q, want RUNNING", resp.DriverState)
	}
	if resp.IsPaused != false {
		t.Errorf("IsPaused = %v, want false", resp.IsPaused)
	}
	if resp.Stats.PacketsRecv != 1500 {
		t.Errorf("PacketsRecv = %d, want 1500", resp.Stats.PacketsRecv)
	}
	if resp.Stats.FakePacketsInjected != 250 {
		t.Errorf("FakePacketsInjected = %d, want 250", resp.Stats.FakePacketsInjected)
	}
	if resp.Stats.OutOfOrderSegmentsInjected != 500 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 500", resp.Stats.OutOfOrderSegmentsInjected)
	}
	if resp.Stats.RetransmissionsDetected != 7 {
		t.Errorf("RetransmissionsDetected = %d, want 7", resp.Stats.RetransmissionsDetected)
	}
	if resp.Stats.StrategyEscalations != 5 {
		t.Errorf("StrategyEscalations = %d, want 5", resp.Stats.StrategyEscalations)
	}
	if resp.Stats.DomainsAutoLearned != 2 {
		t.Errorf("DomainsAutoLearned = %d, want 2", resp.Stats.DomainsAutoLearned)
	}
	if len(resp.LearnedDomains) != 2 {
		t.Fatalf("len(LearnedDomains) = %d, want 2", len(resp.LearnedDomains))
	}
	if resp.LearnedDomains[0].Domain != "updates.discord.com" || resp.LearnedDomains[0].Stage != 2 {
		t.Errorf("LearnedDomains[0] mismatch: %+v", resp.LearnedDomains[0])
	}
}

func TestWebUI_PauseResumeStateTransitions(t *testing.T) {
	ctrl := &mockEngineController{
		mode:        "packet",
		strategy:    "TTL 5 + OOO Split",
		driverState: "RUNNING",
		paused:      false,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer("127.0.0.1:8787", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// 1. Pause
	pauseReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/pause", nil)
	pauseReq.Host = "127.0.0.1:8787"
	pauseRR := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(pauseRR, pauseReq)

	if pauseRR.Code != http.StatusOK {
		t.Fatalf("pause status = %d, want 200", pauseRR.Code)
	}
	if !ctrl.IsPaused() {
		t.Fatal("controller should be paused after pause endpoint call")
	}
	if ctrl.DriverState() != "STOPPED" {
		t.Fatalf("driver state = %q, want STOPPED", ctrl.DriverState())
	}

	// 2. Resume
	resumeReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/driver/resume", nil)
	resumeReq.Host = "127.0.0.1:8787"
	resumeRR := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(resumeRR, resumeReq)

	if resumeRR.Code != http.StatusOK {
		t.Fatalf("resume status = %d, want 200", resumeRR.Code)
	}
	if ctrl.IsPaused() {
		t.Fatal("controller should not be paused after resume endpoint call")
	}
	if ctrl.DriverState() != "RUNNING" {
		t.Fatalf("driver state = %q, want RUNNING", ctrl.DriverState())
	}
}

func TestWebUI_DashboardRendering(t *testing.T) {
	ctrl := &mockEngineController{mode: "packet", driverState: "RUNNING"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer("127.0.0.1:8787", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/", nil)
	req.Host = "127.0.0.1:8787"
	rr := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "dpibypass Engine") {
		t.Fatal("dashboard missing title 'dpibypass Engine'")
	}
	if !strings.Contains(body, "Anti-Cheat Safe Mode") {
		t.Fatal("dashboard missing Anti-Cheat Safe Mode section")
	}
	if !strings.Contains(body, "/api/stats") {
		t.Fatal("dashboard missing stats polling script")
	}
}

func TestWebUI_StartAndShutdown(t *testing.T) {
	ctrl := &mockEngineController{mode: "packet", driverState: "RUNNING"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Bind to port 0 on loopback for dynamic free port
	srv, err := NewServer("127.0.0.1:0", ctrl, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()

	// Wait briefly for listener
	for i := 0; i < 20; i++ {
		if srv.Addr() != "127.0.0.1:0" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	addr := srv.Addr()
	if addr == "127.0.0.1:0" || addr == "" {
		t.Fatalf("listener did not bind to valid port: %s", addr)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

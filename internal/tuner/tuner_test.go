package tuner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/diagnostics"
	"dpibypass/internal/strategy"
)

type deterministicResolver struct {
	ip net.IP
}

func (d *deterministicResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{d.ip}, nil
}

func setupTestTLSServer(t *testing.T, host string, statusCode int) (string, *x509.CertPool, func()) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool.AddCert(parsed)

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte("SERVER_RESPONSE"))
		}),
	}
	go func() {
		_ = server.Serve(tlsLn)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = tlsLn.Close()
	}

	return tlsLn.Addr().String(), pool, cleanup
}

func TestTunerBaselineSuccess(t *testing.T) {
	// If baseline succeeds consistently, recommendation MUST be "none"
	addr, pool, cleanup := setupTestTLSServer(t, "baseline-ok.local", http.StatusOK)
	defer cleanup()

	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"write-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	cfg := TunerConfig{
		Trials:     3,
		InterDelay: 10 * time.Millisecond,
		Port:       port,
		Profiles:   profiles,
		CheckerConfig: diagnostics.CheckerConfig{
			DialTimeout:      2 * time.Second,
			DNSTimeout:       2 * time.Second,
			HandshakeTimeout: 2 * time.Second,
			HTTPTimeout:      2 * time.Second,
			RootCAs:          pool,
			Resolver:         &deterministicResolver{ip: net.ParseIP("127.0.0.1")},
		},
	}

	ctx := context.Background()
	res := TuneDomain(ctx, "baseline-ok.local", []string{"write-split"}, cfg)

	if !res.IsConclusive {
		t.Fatal("expected conclusive result when baseline succeeds")
	}
	if res.RecommendedProfile != "none" {
		t.Fatalf("expected recommended profile 'none', got %q", res.RecommendedProfile)
	}
	if !strings.Contains(res.RecommendationReason, "unnecessary") {
		t.Errorf("unexpected rationale: %s", res.RecommendationReason)
	}

	// Verify report formatting runs without panic
	report := FormatReport([]DomainTuneResult{res})
	if !strings.Contains(report, "baseline-ok.local") || !strings.Contains(report, "Recommendation : none") {
		t.Errorf("report output missing expected content:\n%s", report)
	}
}

func TestTunerInconclusiveOnTotalFailure(t *testing.T) {
	// Point to closed port: both baseline and candidates will fail connect
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"write-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	cfg := TunerConfig{
		Trials:     2,
		InterDelay: 5 * time.Millisecond,
		Port:       port,
		Profiles:   profiles,
		CheckerConfig: diagnostics.CheckerConfig{
			DialTimeout:      500 * time.Millisecond,
			DNSTimeout:       500 * time.Millisecond,
			HandshakeTimeout: 500 * time.Millisecond,
			HTTPTimeout:      500 * time.Millisecond,
			Resolver:         &deterministicResolver{ip: net.ParseIP("127.0.0.1")},
		},
	}

	ctx := context.Background()
	res := TuneDomain(ctx, "fail.local", []string{"write-split"}, cfg)

	if res.IsConclusive {
		t.Fatal("expected inconclusive result when all profiles fail")
	}
	if res.RecommendedProfile != "" {
		t.Fatalf("expected empty recommended profile, got %q", res.RecommendedProfile)
	}
	if !strings.Contains(res.RecommendationReason, "Inconclusive") {
		t.Errorf("unexpected rationale: %s", res.RecommendationReason)
	}
}

func TestTunerPositiveRecommendationAndConsistency(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"write-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	trials := 3
	checkFn := func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult {
		if strat.Name() == "none" {
			return diagnostics.CheckResult{
				Domain:        domain,
				Port:          port,
				StrategyName:  "none",
				Outcome:       diagnostics.OutcomeTLSHandshakeFailure,
				FailureReason: "handshake timeout",
				TotalDuration: 2000 * time.Millisecond,
			}
		}
		return diagnostics.CheckResult{
			Domain:          domain,
			Port:            port,
			StrategyName:    strat.Name(),
			StrategyApplied: true,
			Outcome:         diagnostics.OutcomeSuccess,
			HTTPStatusCode:  200,
			TotalDuration:   120 * time.Millisecond,
		}
	}

	cfg := TunerConfig{
		Trials:     trials,
		InterDelay: 0,
		Port:       443,
		Profiles:   profiles,
		CheckFunc:  checkFn,
	}

	res := TuneDomain(context.Background(), "blocked.example.com", []string{"write-split"}, cfg)

	if !res.IsConclusive {
		t.Fatal("expected conclusive result when candidate succeeds over failing baseline")
	}
	if res.RecommendedProfile != "write-split" {
		t.Fatalf("expected recommendation 'write-split', got %q", res.RecommendedProfile)
	}

	// Verify trial counts, failure classifications, and internal consistency
	if res.BaselineStats.Trials != trials || res.BaselineStats.Failures != trials || res.BaselineStats.Successes != 0 {
		t.Fatalf("inconsistent baseline stats: %+v", res.BaselineStats)
	}
	if res.BaselineStats.FailureClasses[diagnostics.OutcomeTLSHandshakeFailure] != trials {
		t.Fatalf("expected %d handshake timeouts, got %d", trials, res.BaselineStats.FailureClasses[diagnostics.OutcomeTLSHandshakeFailure])
	}
	if res.BaselineStats.DominantOutcome != diagnostics.OutcomeTLSHandshakeFailure {
		t.Fatalf("expected dominant outcome TLSHandshakeFailure, got %v", res.BaselineStats.DominantOutcome)
	}

	if len(res.CandidateStats) != 1 {
		t.Fatalf("expected 1 candidate stat, got %d", len(res.CandidateStats))
	}
	cand := res.CandidateStats[0]
	if cand.Trials != trials || cand.Successes != trials || cand.Failures != 0 {
		t.Fatalf("inconsistent candidate stats: %+v", cand)
	}
	if cand.DominantOutcome != diagnostics.OutcomeSuccess {
		t.Fatalf("expected dominant outcome Success, got %v", cand.DominantOutcome)
	}
	if cand.AvgLatency != 120*time.Millisecond {
		t.Fatalf("expected avg latency 120ms, got %v", cand.AvgLatency)
	}
}

func TestTunerIntermittentBaselineInconclusive(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"write-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	baselineCalls := 0
	checkFn := func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult {
		if strat.Name() == "none" {
			baselineCalls++
			if baselineCalls == 1 {
				return diagnostics.CheckResult{
					Outcome:       diagnostics.OutcomeSuccess,
					TotalDuration: 50 * time.Millisecond,
				}
			}
			return diagnostics.CheckResult{
				Outcome:       diagnostics.OutcomeTLSHandshakeFailure,
				FailureReason: "timeout",
			}
		}
		return diagnostics.CheckResult{
			Outcome:         diagnostics.OutcomeSuccess,
			StrategyApplied: true,
			TotalDuration:   50 * time.Millisecond,
		}
	}

	cfg := TunerConfig{
		Trials:     3,
		InterDelay: 0,
		Port:       443,
		Profiles:   profiles,
		CheckFunc:  checkFn,
	}

	res := TuneDomain(context.Background(), "intermittent.example.com", []string{"write-split"}, cfg)

	if res.IsConclusive {
		t.Fatal("expected inconclusive result for intermittent baseline")
	}
	if res.RecommendedProfile != "" {
		t.Fatalf("expected empty recommendation, got %q", res.RecommendedProfile)
	}
	if !strings.Contains(res.RecommendationReason, "intermittent") {
		t.Errorf("expected mention of intermittent in reason, got: %s", res.RecommendationReason)
	}
}

func TestTunerLatencyTieBreaking(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"none":       {Type: "none"},
		"fast-split": {Type: "tcp-write-split", Offset: "sni-mid"},
		"slow-split": {Type: "tls-record-split", Offset: "sni-mid"},
	}

	checkFn := func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult {
		if strat.Name() == "none" {
			return diagnostics.CheckResult{Outcome: diagnostics.OutcomeTimeout}
		}
		lat := 200 * time.Millisecond
		if strat.Name() == "tcp-write-split" {
			lat = 50 * time.Millisecond
		}
		return diagnostics.CheckResult{
			Outcome:         diagnostics.OutcomeSuccess,
			StrategyApplied: true,
			TotalDuration:   lat,
		}
	}

	cfg := TunerConfig{
		Trials:     3,
		InterDelay: 0,
		Port:       443,
		Profiles:   profiles,
		CheckFunc:  checkFn,
	}

	res := TuneDomain(context.Background(), "tiebreak.example.com", []string{"slow-split", "fast-split"}, cfg)

	if !res.IsConclusive {
		t.Fatal("expected conclusive result")
	}
	if res.RecommendedProfile != "fast-split" {
		t.Fatalf("expected faster profile 'fast-split' to be recommended, got %q", res.RecommendedProfile)
	}
}

func TestTunerUnsupportedCandidateExcluded(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"unsupported": {Type: "http-host-tweak"},
		"valid-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	checkFn := func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult {
		if strat.Name() == "none" {
			return diagnostics.CheckResult{Outcome: diagnostics.OutcomeTLSHandshakeFailure}
		}
		if strat.Name() == "http-host-tweak" {
			return diagnostics.CheckResult{
				Outcome:       diagnostics.OutcomeUnsupportedStrategy,
				FailureReason: "unsupported on TLS",
			}
		}
		return diagnostics.CheckResult{
			Outcome:         diagnostics.OutcomeSuccess,
			StrategyApplied: true,
			TotalDuration:   80 * time.Millisecond,
		}
	}

	cfg := TunerConfig{
		Trials:     3,
		InterDelay: 0,
		Port:       443,
		Profiles:   profiles,
		CheckFunc:  checkFn,
	}

	res := TuneDomain(context.Background(), "unsupported-test.example.com", []string{"unsupported", "valid-split"}, cfg)

	if !res.IsConclusive {
		t.Fatal("expected conclusive result when valid candidate exists")
	}
	if res.RecommendedProfile != "valid-split" {
		t.Fatalf("expected 'valid-split', got %q", res.RecommendedProfile)
	}

	var foundUnsupported bool
	for _, c := range res.CandidateStats {
		if c.ProfileName == "unsupported" {
			foundUnsupported = true
			if !c.Unsupported {
				t.Error("expected candidate to be marked Unsupported")
			}
		}
	}
	if !foundUnsupported {
		t.Fatal("unsupported candidate stat not found")
	}

	resOnlyUnsupported := TuneDomain(context.Background(), "unsupported-only.example.com", []string{"unsupported"}, cfg)
	if resOnlyUnsupported.IsConclusive {
		t.Fatal("expected inconclusive when only candidate is unsupported")
	}
	if resOnlyUnsupported.RecommendedProfile != "" {
		t.Fatalf("expected empty recommendation, got %q", resOnlyUnsupported.RecommendedProfile)
	}
}

func TestTunerCandidateFailsToImprove(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"none":        {Type: "none"},
		"write-split": {Type: "tcp-write-split", Offset: "sni-mid"},
	}

	checkFn := func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult {
		return diagnostics.CheckResult{
			Outcome:       diagnostics.OutcomeTLSHandshakeFailure,
			FailureReason: "timeout",
		}
	}

	cfg := TunerConfig{
		Trials:     3,
		InterDelay: 0,
		Port:       443,
		Profiles:   profiles,
		CheckFunc:  checkFn,
	}

	res := TuneDomain(context.Background(), "no-improve.example.com", []string{"write-split"}, cfg)

	if res.IsConclusive {
		t.Fatal("expected inconclusive result when candidate does not improve")
	}
	if res.RecommendedProfile != "" {
		t.Fatalf("expected empty recommendation, got %q", res.RecommendedProfile)
	}
}

func TestTunerInconclusiveCannotTriggerApply(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")
	initialContent := "{\"listen_port\":8080,\"default_profile\":\"none\",\"profiles\":{\"none\":{\"type\":\"none\"}}}"
	if err := os.WriteFile(cfgPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	inconclusiveRes := DomainTuneResult{
		Domain:               "example.com",
		RecommendedProfile:   "",
		RecommendationReason: "Inconclusive results",
		IsConclusive:         false,
	}

	_, err := SafeApplyRecommendation(cfgPath, []DomainTuneResult{inconclusiveRes})
	if err == nil {
		t.Fatal("expected error applying inconclusive result, got nil")
	}
	if !strings.Contains(err.Error(), "no conclusive strategy improvements") {
		t.Fatalf("expected 'no conclusive strategy improvements' in error, got: %v", err)
	}

	content, err := os.ReadFile(cfgPath)
	if err != nil || string(content) != initialContent {
		t.Fatalf("config file was modified after inconclusive apply attempt: %s", string(content))
	}
	if _, err := os.Stat(cfgPath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("backup file should not have been created for inconclusive apply")
	}
}

package diagnostics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/strategy"
)

// mockResolver implements Resolver interface for deterministic testing.
type mockResolver struct {
	ips []net.IP
	err error
}

func (m *mockResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ips, nil
}

func generateCertForName(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName},
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

	return cert, pool
}

func TestCheckerInvalidInputs(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultCheckerConfig()

	// Empty domain
	res := RunCheck(ctx, "", 443, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeInvalidConfig {
		t.Errorf("expected OutcomeInvalidConfig for empty domain, got %v", res.Outcome)
	}

	// Wildcard domain
	res = RunCheck(ctx, "*.example.com", 443, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeInvalidConfig {
		t.Errorf("expected OutcomeInvalidConfig for wildcard domain, got %v", res.Outcome)
	}

	// Invalid port
	res = RunCheck(ctx, "example.com", 0, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeInvalidConfig {
		t.Errorf("expected OutcomeInvalidConfig for port 0, got %v", res.Outcome)
	}

	// Unsupported strategy: http-host-tweak on TLS port 443
	hostStrat := strategy.NewHTTPHostTweakStrategy("lowercase", 0)
	res = RunCheck(ctx, "example.com", 443, hostStrat, cfg)
	if res.Outcome != OutcomeUnsupportedStrategy {
		t.Errorf("expected OutcomeUnsupportedStrategy for http-host-tweak on TLS, got %v", res.Outcome)
	}
}

func TestCheckerDNSFailure(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultCheckerConfig()
	cfg.Resolver = &mockResolver{err: errors.New("no such host")}

	res := RunCheck(ctx, "nonexistent.domain.test", 443, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeDNSFailure {
		t.Errorf("expected OutcomeDNSFailure, got %v", res.Outcome)
	}
}

func TestCheckerTCPConnectFailure(t *testing.T) {
	// Listen and immediately close to get a free, closed port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx := context.Background()
	cfg := DefaultCheckerConfig()
	cfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	res := RunCheck(ctx, "127.0.0.1", port, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeTCPConnectionFailure {
		t.Errorf("expected OutcomeTCPConnectionFailure for closed port, got %v (%s)", res.Outcome, res.FailureReason)
	}
}

func TestCheckerTLSCertVerificationFailure(t *testing.T) {
	// Server certificate is valid only for "server.local"
	cert, pool := generateCertForName(t, "server.local")

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer tlsLn.Close()

	go func() {
		conn, err := tlsLn.Accept()
		if err == nil && conn != nil {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx := context.Background()
	cfg := DefaultCheckerConfig()
	cfg.RootCAs = pool
	cfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	// Probe targeting "wrong.domain.local" must fail certificate validation
	res := RunCheck(ctx, "wrong.domain.local", port, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeCertVerificationFailure {
		t.Errorf("expected OutcomeCertVerificationFailure on hostname mismatch, got %v (%s)", res.Outcome, res.FailureReason)
	}
}

func TestCheckerTLSSuccessAcrossStrategies(t *testing.T) {
	cert, pool := generateCertForName(t, "test.local")

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer tlsLn.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK_DIAGNOSTICS"))
		}),
	}
	go func() {
		_ = server.Serve(tlsLn)
	}()
	defer server.Close()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := DefaultCheckerConfig()
	cfg.RootCAs = pool
	cfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	strategiesToTest := []struct {
		name  string
		strat strategy.Strategy
	}{
		{"none", strategy.NewNoneStrategy()},
		{"tcp-write-split", strategy.NewTCPWriteSplitStrategy("sni-mid", 0)},
		{"multi-write-split", strategy.NewMultiWriteSplitStrategy(16, 8, 0)},
		{"tls-record-split", strategy.NewTLSRecordSplitStrategy("sni-mid")},
		{"composite", strategy.NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0)},
	}

	for _, tc := range strategiesToTest {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res := RunCheck(ctx, "test.local", port, tc.strat, cfg)
			if res.Outcome != OutcomeSuccess {
				t.Fatalf("expected OutcomeSuccess under %s, got %v (%s)", tc.name, res.Outcome, res.FailureReason)
			}
			if res.HTTPStatusCode != 200 {
				t.Errorf("expected HTTP 200, got %d", res.HTTPStatusCode)
			}
			if tc.name != "none" && !res.StrategyApplied {
				t.Errorf("expected StrategyApplied=true for strategy %s", tc.name)
			}
		})
	}
}

func TestCheckerHTTPRestrictedClassification(t *testing.T) {
	cert, pool := generateCertForName(t, "restricted.local")

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer tlsLn.Close()

	currentStatus := http.StatusForbidden
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(currentStatus)
			_, _ = w.Write([]byte("Access Denied"))
		}),
	}
	go func() {
		_ = server.Serve(tlsLn)
	}()
	defer server.Close()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := DefaultCheckerConfig()
	cfg.RootCAs = pool
	cfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	ctx := context.Background()

	// Test 403 Forbidden
	currentStatus = http.StatusForbidden
	res403 := RunCheck(ctx, "restricted.local", port, strategy.NewNoneStrategy(), cfg)
	if res403.Outcome != OutcomeHTTPRestricted {
		t.Errorf("expected OutcomeHTTPRestricted for HTTP 403, got %v", res403.Outcome)
	}
	if res403.HTTPStatusCode != 403 {
		t.Errorf("expected HTTP 403 status code, got %d", res403.HTTPStatusCode)
	}

	// Test 451 Unavailable For Legal Reasons
	currentStatus = http.StatusUnavailableForLegalReasons
	res451 := RunCheck(ctx, "restricted.local", port, strategy.NewNoneStrategy(), cfg)
	if res451.Outcome != OutcomeHTTPRestricted {
		t.Errorf("expected OutcomeHTTPRestricted for HTTP 451, got %v", res451.Outcome)
	}
	if res451.HTTPStatusCode != 451 {
		t.Errorf("expected HTTP 451 status code, got %d", res451.HTTPStatusCode)
	}
}

func TestCheckerOversizedHeadersRejection(t *testing.T) {
	cert, pool := generateCertForName(t, "huge.local")

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer tlsLn.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write oversized header (> 16 KiB)
			w.Header().Set("X-Huge-Padding", strings.Repeat("A", 20*1024))
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() {
		_ = server.Serve(tlsLn)
	}()
	defer server.Close()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := DefaultCheckerConfig()
	cfg.RootCAs = pool
	cfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	ctx := context.Background()
	res := RunCheck(ctx, "huge.local", port, strategy.NewNoneStrategy(), cfg)
	if res.Outcome != OutcomeHTTPResponseInvalid {
		t.Errorf("expected OutcomeHTTPResponseInvalid for oversized headers, got %v (%s)", res.Outcome, res.FailureReason)
	}
}

func TestCheckerTransportCompatibility(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultCheckerConfig()

	// 1. Port 80 (plain HTTP) with TLS strategies must be rejected with OutcomeUnsupportedStrategy
	tlsStrategies := []strategy.Strategy{
		strategy.NewTCPWriteSplitStrategy("sni-mid", 0),
		strategy.NewMultiWriteSplitStrategy(16, 8, 0),
		strategy.NewTLSRecordSplitStrategy("sni-mid"),
		strategy.NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0),
	}

	for _, strat := range tlsStrategies {
		res := RunCheck(ctx, "example.com", 80, strat, cfg)
		if res.Outcome != OutcomeUnsupportedStrategy {
			t.Errorf("expected OutcomeUnsupportedStrategy for %s on port 80, got %v", strat.Name(), res.Outcome)
		}
		if res.StrategyApplied {
			t.Errorf("expected StrategyApplied=false for unsupported strategy on port 80")
		}
	}

	// 2. Port 80 with local HTTP server: test 'none' and 'http-host-tweak'
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HTTP_OK"))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	plainCfg := cfg
	plainCfg.PlainHTTP = true
	plainCfg.Resolver = &mockResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}

	// none on plain HTTP: must succeed, StrategyApplied=false
	resNone := RunCheck(ctx, "plain.local", port, strategy.NewNoneStrategy(), plainCfg)
	if resNone.Outcome != OutcomeSuccess {
		t.Fatalf("expected OutcomeSuccess for none on plain HTTP, got %v (%s)", resNone.Outcome, resNone.FailureReason)
	}
	if resNone.StrategyApplied {
		t.Error("expected StrategyApplied=false for none strategy on plain HTTP")
	}

	// http-host-tweak on plain HTTP: must succeed, StrategyApplied=true
	hostStrat := strategy.NewHTTPHostTweakStrategy("lowercase", 0)
	resHost := RunCheck(ctx, "plain.local", port, hostStrat, plainCfg)
	if resHost.Outcome != OutcomeSuccess {
		t.Fatalf("expected OutcomeSuccess for http-host-tweak on plain HTTP, got %v (%s)", resHost.Outcome, resHost.FailureReason)
	}
	if !resHost.StrategyApplied {
		t.Error("expected StrategyApplied=true for http-host-tweak on plain HTTP")
	}
}

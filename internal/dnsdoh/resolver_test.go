package dnsdoh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dpibypass/internal/config"
)

// generateTestCert creates an in-memory self-signed certificate and CA pool.
// Strict certificate verification remains enabled in all integration tests; InsecureSkipVerify is NEVER used.
func generateTestCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"DPIBypass DoH Test"},
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{host, "localhost"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse test cert: %v", err)
	}
	certPool.AddCert(parsed)

	return cert, certPool
}

func TestResolverIPLiteralZeroDNS(t *testing.T) {
	// Construct resolver with no endpoints
	res, err := NewResolver(config.DoHConfig{Enabled: false}, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	ctx := context.Background()

	// IPv4 literal
	ips4, err := res.LookupIP(ctx, "93.184.216.34")
	if err != nil {
		t.Fatalf("unexpected error for IPv4 literal: %v", err)
	}
	if len(ips4) != 1 || ips4[0].String() != "93.184.216.34" {
		t.Fatalf("expected [93.184.216.34], got %v", ips4)
	}

	// IPv6 literal
	ips6, err := res.LookupIP(ctx, "2606:2800:220:1:248:1893:25c8:1946")
	if err != nil {
		t.Fatalf("unexpected error for IPv6 literal: %v", err)
	}
	if len(ips6) != 1 || ips6[0].String() != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Fatalf("expected [2606:2800:220:1:248:1893:25c8:1946], got %v", ips6)
	}
}

func TestResolverMockDoHSuccess(t *testing.T) {
	cert, pool := generateTestCert(t, "127.0.0.1")

	// Create HTTPS mock server
	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) < 12 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		queryID := binary.BigEndian.Uint16(body[0:2])
		qtype := binary.BigEndian.Uint16(body[len(body)-4 : len(body)-2])

		buf := makeBaseResponse(queryID, 0x8180, "test.example.com", qtype)
		data := buf.Bytes()
		binary.BigEndian.PutUint16(data[6:8], 1) // ANCOUNT = 1

		ansBuf := new(bytes.Buffer)
		ansBuf.Write([]byte{0xC0, 0x0C})
		_ = binary.Write(ansBuf, binary.BigEndian, qtype)
		_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
		_ = binary.Write(ansBuf, binary.BigEndian, uint32(120)) // TTL 120s

		if qtype == TypeA {
			_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
			ansBuf.Write([]byte{93, 184, 216, 34})
		} else if qtype == TypeAAAA {
			_ = binary.Write(ansBuf, binary.BigEndian, uint16(16))
			ansBuf.Write(net.ParseIP("2606:2800:220:1::1"))
		}

		msg := append(data, ansBuf.Bytes()...)

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(msg)
	}))

	mockServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	mockServer.StartTLS()
	defer mockServer.Close()

	dohConfig := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: false,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          mockServer.URL,
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohConfig, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(pool) // Strict verification against test CA

	ctx := context.Background()
	ips, err := res.LookupIP(ctx, "test.example.com")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (dual-stack A and AAAA), got %d: %v", len(ips), ips)
	}

	// Verify IPv4 preference: first IP must be IPv4
	if ips[0].To4() == nil {
		t.Errorf("expected first IP to be IPv4, got %s", ips[0])
	}
	if ips[1].To4() != nil {
		t.Errorf("expected second IP to be IPv6, got %s", ips[1])
	}

	// Verify subsequent lookup hits cache
	cachedIPs, err := res.LookupIP(ctx, "test.example.com")
	if err != nil {
		t.Fatalf("cached LookupIP: %v", err)
	}
	if len(cachedIPs) != 2 {
		t.Fatalf("expected 2 cached IPs, got %d", len(cachedIPs))
	}
}

func TestResolverRedirectRejection(t *testing.T) {
	cert, pool := generateTestCert(t, "127.0.0.1")

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/somewhere-else", http.StatusFound) // 302 Found
	}))
	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	dohConfig := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: false,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          mockServer.URL,
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohConfig, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(pool)

	_, err = res.LookupIP(context.Background(), "redirect.example.com")
	if err == nil {
		t.Fatal("expected error due to redirect rejection, got nil")
	}
}

func TestResolverContentTypeValidation(t *testing.T) {
	cert, pool := generateTestCert(t, "127.0.0.1")

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // Invalid media type
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Error</html>"))
	}))
	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	dohConfig := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: false,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          mockServer.URL,
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohConfig, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(pool)

	_, err = res.LookupIP(context.Background(), "html.example.com")
	if err == nil {
		t.Fatal("expected error due to invalid Content-Type, got nil")
	}
}

func TestResolverNXDomainDoesNotFallback(t *testing.T) {
	cert, pool := generateTestCert(t, "127.0.0.1")

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queryID := binary.BigEndian.Uint16(body[0:2])
		qtype := binary.BigEndian.Uint16(body[len(body)-4 : len(body)-2])

		// Return NXDOMAIN (RCODE=3) with Authority SOA
		buf := makeBaseResponse(queryID, 0x8183, "nx.example.com", qtype)
		data := buf.Bytes()
		binary.BigEndian.PutUint16(data[8:10], 1) // NSCOUNT = 1

		soaBuf := new(bytes.Buffer)
		soaBuf.WriteByte(7)
		soaBuf.WriteString("example")
		soaBuf.WriteByte(3)
		soaBuf.WriteString("com")
		soaBuf.WriteByte(0)
		_ = binary.Write(soaBuf, binary.BigEndian, TypeSOA)
		_ = binary.Write(soaBuf, binary.BigEndian, ClassINET)
		_ = binary.Write(soaBuf, binary.BigEndian, uint32(300))

		rdata := new(bytes.Buffer)
		rdata.Write([]byte{2, 'n', 's', 0})
		rdata.Write([]byte{4, 'h', 'o', 's', 't', 0})
		_ = binary.Write(rdata, binary.BigEndian, uint32(1))
		_ = binary.Write(rdata, binary.BigEndian, uint32(7200))
		_ = binary.Write(rdata, binary.BigEndian, uint32(3600))
		_ = binary.Write(rdata, binary.BigEndian, uint32(1200))
		_ = binary.Write(rdata, binary.BigEndian, uint32(300))

		_ = binary.Write(soaBuf, binary.BigEndian, uint16(rdata.Len()))
		soaBuf.Write(rdata.Bytes())

		msg := append(data, soaBuf.Bytes()...)

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(msg)
	}))
	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	dohConfig := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: true, // System fallback enabled, but MUST NOT be triggered for NXDOMAIN!
		Endpoints: []config.DoHEndpoint{
			{
				URL:          mockServer.URL,
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohConfig, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(pool)

	_, err = res.LookupIP(context.Background(), "nx.example.com")
	if !errors.Is(err, ErrNXDomain) && !errors.Is(err, ErrNoData) {
		t.Fatalf("expected ErrNXDomain or ErrNoData, got %v", err)
	}
}

func TestResolverTransportErrorFallbackHandling(t *testing.T) {
	cert, pool := generateTestCert(t, "127.0.0.1")

	// Mock server always returns HTTP 500 (transport/service failure)
	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	t.Run("fails when FallbackSystem is false", func(t *testing.T) {
		dohConfig := config.DoHConfig{
			Enabled:        true,
			FallbackSystem: false,
			Endpoints: []config.DoHEndpoint{
				{
					URL:          mockServer.URL,
					BootstrapIPs: []string{"127.0.0.1"},
				},
			},
		}

		res, err := NewResolver(dohConfig, slog.Default())
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
		res.SetRootCAs(pool)

		_, err = res.LookupIP(context.Background(), "fail.example.com")
		if err == nil {
			t.Fatal("expected error when FallbackSystem is false, got nil")
		}
	})

	t.Run("falls back to system resolver when FallbackSystem is true", func(t *testing.T) {
		dohConfig := config.DoHConfig{
			Enabled:        true,
			FallbackSystem: true,
			Endpoints: []config.DoHEndpoint{
				{
					URL:          mockServer.URL,
					BootstrapIPs: []string{"127.0.0.1"},
				},
			},
		}

		res, err := NewResolver(dohConfig, slog.Default())
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
		res.SetRootCAs(pool)

		// Resolving localhost should succeed via system resolver
		ips, err := res.LookupIP(context.Background(), "localhost")
		if err != nil {
			t.Fatalf("expected system resolver fallback for localhost to succeed, got %v", err)
		}
		if len(ips) == 0 {
			t.Fatal("expected at least 1 IP for localhost")
		}
	})
}

func TestResolverStrictTLSFailure(t *testing.T) {
	// Generate cert for "127.0.0.1", but DO NOT add to cert pool
	cert, _ := generateTestCert(t, "127.0.0.1")
	otherPool := x509.NewCertPool() // Empty pool -> verification must fail!

	mockServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mockServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	mockServer.StartTLS()
	defer mockServer.Close()

	dohConfig := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: false,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          mockServer.URL,
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohConfig, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(otherPool) // Untrusted pool

	_, err = res.LookupIP(context.Background(), "tls.example.com")
	if err == nil {
		t.Fatal("expected strict TLS verification failure, got nil")
	}
}

func TestResolveQueryType_IPLiterals(t *testing.T) {
	dohCfg := config.DoHConfig{
		Enabled: true,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          "https://127.0.0.1:443/dns-query",
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}
	res, err := NewResolver(dohCfg, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	ctx := context.Background()

	// 1. IPv4 literal queried for TypeA -> returns the IPv4
	ipsA, ttl, isNoData, err := res.ResolveQueryType(ctx, "93.184.216.34", TypeA)
	if err != nil || isNoData {
		t.Fatalf("expected IPv4 literal for TypeA to succeed, got err=%v, isNoData=%v", err, isNoData)
	}
	if len(ipsA) != 1 || !ipsA[0].Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("unexpected IPs: %v", ipsA)
	}
	if ttl <= 0 {
		t.Errorf("expected positive TTL, got %v", ttl)
	}

	// 2. IPv4 literal queried for TypeAAAA -> returns NODATA
	ipsAAAA, _, isNoData, err := res.ResolveQueryType(ctx, "93.184.216.34", TypeAAAA)
	if err != nil {
		t.Fatalf("expected nil error for IPv4 literal TypeAAAA query, got %v", err)
	}
	if !isNoData || len(ipsAAAA) != 0 {
		t.Errorf("expected isNoData=true, got isNoData=%v, ips=%v", isNoData, ipsAAAA)
	}

	// 3. IPv6 literal queried for TypeAAAA -> returns the IPv6
	v6Str := "2606:4700::6810:82e9"
	ips6, _, isNoData, err := res.ResolveQueryType(ctx, v6Str, TypeAAAA)
	if err != nil || isNoData {
		t.Fatalf("expected IPv6 literal for TypeAAAA to succeed, got err=%v, isNoData=%v", err, isNoData)
	}
	if len(ips6) != 1 || !ips6[0].Equal(net.ParseIP(v6Str)) {
		t.Errorf("unexpected IPs: %v", ips6)
	}

	// 4. IPv6 literal queried for TypeA -> returns NODATA
	ipsA6, _, isNoData, err := res.ResolveQueryType(ctx, v6Str, TypeA)
	if err != nil {
		t.Fatalf("expected nil error for IPv6 literal TypeA query, got %v", err)
	}
	if !isNoData || len(ipsA6) != 0 {
		t.Errorf("expected isNoData=true, got isNoData=%v, ips=%v", isNoData, ipsA6)
	}
}

func TestResolveQueryType_CacheRemainingTTL(t *testing.T) {
	dohCfg := config.DoHConfig{
		Enabled: true,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          "https://127.0.0.1:443/dns-query",
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}
	res, err := NewResolver(dohCfg, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	now := time.Now()
	testIP := net.ParseIP("192.0.2.1")
	res.cache.PutPositive("cached.example.com", TypeA, []net.IP{testIP}, 120*time.Second, now)

	ctx := context.Background()
	ips, remTTL, isNoData, err := res.ResolveQueryType(ctx, "cached.example.com", TypeA)
	if err != nil || isNoData {
		t.Fatalf("ResolveQueryType failed on cache hit: err=%v, isNoData=%v", err, isNoData)
	}
	if len(ips) != 1 || !ips[0].Equal(testIP) {
		t.Errorf("unexpected IPs: %v", ips)
	}
	if remTTL <= 0 || remTTL > 120*time.Second {
		t.Errorf("expected remaining TTL between 0 and 120s, got %v", remTTL)
	}
}

func TestResolveQueryType_DisabledAndEmpty(t *testing.T) {
	ctx := context.Background()

	// Empty domain
	res, _ := NewResolver(config.DoHConfig{Enabled: true}, slog.Default())
	_, _, _, err := res.ResolveQueryType(ctx, "", TypeA)
	if err == nil {
		t.Error("expected error for empty domain, got nil")
	}

	// Disabled resolver
	disabledRes, _ := NewResolver(config.DoHConfig{Enabled: false}, slog.Default())
	_, _, _, err = disabledRes.ResolveQueryType(ctx, "example.com", TypeA)
	if err == nil {
		t.Error("expected error when DoH resolver is disabled, got nil")
	}
}

func TestResolverDialsBootstrapIPWithoutDNS(t *testing.T) {
	cert, pool := generateTestCert(t, "cloudflare-dns.com")

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, serverTLSConfig)
	defer tlsLn.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		defer req.Body.Close()

		body, err := io.ReadAll(req.Body)
		if err != nil || len(body) < 12 {
			return
		}

		queryID := binary.BigEndian.Uint16(body[0:2])
		qtype := binary.BigEndian.Uint16(body[len(body)-4 : len(body)-2])

		buf := makeBaseResponse(queryID, 0x8180, "test.example.com", qtype)
		data := buf.Bytes()
		binary.BigEndian.PutUint16(data[6:8], 1) // ANCOUNT = 1

		ansBuf := new(bytes.Buffer)
		ansBuf.Write([]byte{0xC0, 0x0C})
		_ = binary.Write(ansBuf, binary.BigEndian, qtype)
		_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
		_ = binary.Write(ansBuf, binary.BigEndian, uint32(120))
		_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
		ansBuf.Write([]byte{93, 184, 216, 34})

		msg := append(data, ansBuf.Bytes()...)

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(msg)),
			ContentLength: int64(len(msg)),
		}
		resp.Header.Set("Content-Type", "application/dns-message")
		_ = resp.Write(conn)
	}()

	dohCfg := config.DoHConfig{
		Enabled:        true,
		FallbackSystem: false,
		Endpoints: []config.DoHEndpoint{
			{
				URL:          fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port),
				BootstrapIPs: []string{"127.0.0.1"},
			},
		},
	}

	res, err := NewResolver(dohCfg, slog.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res.SetRootCAs(pool)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, remTTL, isNoData, err := res.ResolveQueryType(ctx, "test.example.com", TypeA)
	if err != nil {
		t.Fatalf("ResolveQueryType failed: %v", err)
	}
	if isNoData {
		t.Fatal("unexpected NODATA")
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("expected [93.184.216.34], got %v", ips)
	}
	if remTTL <= 0 {
		t.Fatalf("expected positive remTTL, got %v", remTTL)
	}
}

func TestResolverDirectIPEndpoint(t *testing.T) {
	client, err := NewDoHClient(config.DoHEndpoint{
		URL: "https://1.1.1.1/dns-query",
	}, 2*time.Second)
	if err != nil {
		t.Fatalf("NewDoHClient with direct IP endpoint failed: %v", err)
	}
	if len(client.bootstrapIPs) != 1 || client.bootstrapIPs[0] != "1.1.1.1" {
		t.Fatalf("expected bootstrapIPs to be [1.1.1.1], got %v", client.bootstrapIPs)
	}
}

func TestResolverAutoBootstrapKnownHostnames(t *testing.T) {
	clientCF, err := NewDoHClient(config.DoHEndpoint{
		URL: "https://cloudflare-dns.com/dns-query",
	}, 2*time.Second)
	if err != nil {
		t.Fatalf("NewDoHClient cloudflare-dns.com failed: %v", err)
	}
	if len(clientCF.bootstrapIPs) != 2 || clientCF.bootstrapIPs[0] != "1.1.1.1" {
		t.Fatalf("expected cloudflare bootstrap IPs, got %v", clientCF.bootstrapIPs)
	}

	clientGoogle, err := NewDoHClient(config.DoHEndpoint{
		URL: "https://dns.google/dns-query",
	}, 2*time.Second)
	if err != nil {
		t.Fatalf("NewDoHClient dns.google failed: %v", err)
	}
	if len(clientGoogle.bootstrapIPs) != 2 || clientGoogle.bootstrapIPs[0] != "8.8.8.8" {
		t.Fatalf("expected google bootstrap IPs, got %v", clientGoogle.bootstrapIPs)
	}
}

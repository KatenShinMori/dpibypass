package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
)

// generateTestCertificate creates an in-memory self-signed certificate and CA pool for tests.
// Strict certificate verification remains enabled in all integration tests; InsecureSkipVerify is NEVER used.
func generateTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"DPIBypass Test"},
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "test.local"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	certPool.AddCert(parsed)

	return cert, certPool
}

func startTestTLSServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start test TLS listener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SECURE_PAYLOAD_OK"))
	})

	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(ln)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func TestLocalTLSIntegrationAcrossStrategies(t *testing.T) {
	cert, certPool := generateTestCertificate(t)
	serverAddr, serverCleanup := startTestTLSServer(t, cert)
	defer serverCleanup()

	strategyProfiles := []struct {
		name    string
		profile config.ProfileConfig
	}{
		{
			name:    "none",
			profile: config.ProfileConfig{Type: "none"},
		},
		{
			name:    "tcp-write-split_sni-mid",
			profile: config.ProfileConfig{Type: "tcp-write-split", Offset: "sni-mid"},
		},
		{
			name:    "tcp-write-split_fixed_offset",
			profile: config.ProfileConfig{Type: "tcp-write-split", Offset: "20"},
		},
		{
			name:    "multi-write-split",
			profile: config.ProfileConfig{Type: "multi-write-split", ChunkSize: 16, MaxChunks: 8},
		},
		{
			name:    "tls-record-split_sni-mid",
			profile: config.ProfileConfig{Type: "tls-record-split", Offset: "sni-mid"},
		},
		{
			name:    "composite_record_and_write_split",
			profile: config.ProfileConfig{Type: "tls-record-then-write-split", Offset: "sni-mid"},
		},
	}

	for _, tt := range strategyProfiles {
		t.Run(tt.name, func(t *testing.T) {
			// Start local proxy listener for this test case
			proxyLn, err := ListenLoopback("127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start proxy listener: %v", err)
			}
			defer proxyLn.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			cfg := HandlerConfig{
				DialTimeout:              2 * time.Second,
				IdleTimeout:              5 * time.Second,
				InitialInspectionTimeout: 500 * time.Millisecond,
				MaxInitialBytes:          65536,
				DefaultProfile:           tt.profile,
			}

			go func() {
				for {
					conn, err := proxyLn.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						dialer := &NetDialer{Timeout: 2 * time.Second}
						_ = ServeConn(ctx, c, dialer, logger, cfg)
					}(conn)
				}
			}()

			// Test 1: Full TLS handshake & HTTP exchange via HTTP CONNECT
			t.Run("http_connect", func(t *testing.T) {
				proxyConn, err := net.Dial("tcp", proxyLn.Addr().String())
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				defer proxyConn.Close()

				// Send CONNECT request
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", serverAddr, serverAddr)
				if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
					t.Fatalf("write CONNECT: %v", err)
				}

				// Read 200 Connection Established
				br := bufio.NewReader(proxyConn)
				line, err := br.ReadString('\n')
				if err != nil || !strings.Contains(line, "200") {
					t.Fatalf("expected 200, got %q, err: %v", line, err)
				}
				// Discard remaining CONNECT headers until empty line
				for {
					hdrLine, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(hdrLine) == "" {
						break
					}
				}

				// Establish real TLS client over proxy connection with STRICT certificate verification
				tlsClient := tls.Client(proxyConn, &tls.Config{
					RootCAs:    certPool,
					ServerName: "127.0.0.1",
				})
				defer tlsClient.Close()

				if err := tlsClient.HandshakeContext(ctx); err != nil {
					t.Fatalf("TLS handshake failed through proxy under strategy %q: %v", tt.name, err)
				}

				// Send HTTP request inside the TLS connection
				httpReq := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
				if _, err := tlsClient.Write([]byte(httpReq)); err != nil {
					t.Fatalf("write HTTP request: %v", err)
				}

				respBytes, err := io.ReadAll(tlsClient)
				if err != nil {
					t.Fatalf("read HTTP response: %v", err)
				}

				if !strings.Contains(string(respBytes), "SECURE_PAYLOAD_OK") {
					t.Fatalf("expected payload SECURE_PAYLOAD_OK, got: %s", string(respBytes))
				}
			})

			// Test 2: Full TLS handshake & HTTP exchange via SOCKS5 CONNECT
			t.Run("socks5_connect", func(t *testing.T) {
				proxyConn, err := net.Dial("tcp", proxyLn.Addr().String())
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				defer proxyConn.Close()

				// 1. SOCKS5 greeting
				if _, err := proxyConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
					t.Fatalf("write SOCKS5 greeting: %v", err)
				}
				greetingResp := make([]byte, 2)
				if _, err := io.ReadFull(proxyConn, greetingResp); err != nil {
					t.Fatalf("read SOCKS5 greeting resp: %v", err)
				}
				if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
					t.Fatalf("unexpected greeting resp: %v", greetingResp)
				}

				// 2. SOCKS5 connect to 127.0.0.1:port
				host, portStr, _ := net.SplitHostPort(serverAddr)
				var port uint16
				_, _ = fmt.Sscanf(portStr, "%d", &port)
				ip := net.ParseIP(host).To4()

				connectCmd := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
				if _, err := proxyConn.Write(connectCmd); err != nil {
					t.Fatalf("write SOCKS5 connect: %v", err)
				}

				reply := make([]byte, 10)
				if _, err := io.ReadFull(proxyConn, reply); err != nil {
					t.Fatalf("read SOCKS5 reply: %v", err)
				}
				if reply[1] != 0x00 {
					t.Fatalf("SOCKS5 connect failed with reply code 0x%02x", reply[1])
				}

				// 3. Establish TLS client with STRICT certificate verification
				tlsClient := tls.Client(proxyConn, &tls.Config{
					RootCAs:    certPool,
					ServerName: "127.0.0.1",
				})
				defer tlsClient.Close()

				if err := tlsClient.HandshakeContext(ctx); err != nil {
					t.Fatalf("SOCKS5 TLS handshake failed under strategy %q: %v", tt.name, err)
				}

				// Send HTTP request
				httpReq := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
				if _, err := tlsClient.Write([]byte(httpReq)); err != nil {
					t.Fatalf("write HTTP request: %v", err)
				}

				respBytes, err := io.ReadAll(tlsClient)
				if err != nil {
					t.Fatalf("read HTTP response: %v", err)
				}

				if !strings.Contains(string(respBytes), "SECURE_PAYLOAD_OK") {
					t.Fatalf("expected payload SECURE_PAYLOAD_OK, got: %s", string(respBytes))
				}
			})
		})
	}
}

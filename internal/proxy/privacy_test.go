package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTargetLogAttrPrivacy(t *testing.T) {
	const (
		sentinelDomain = "secret-corp.example.org"
		sentinelPort   = "54321"
		sentinelIPv4   = "198.51.100.42"
		sentinelIPv6   = "2001:db8::dead:beef"
	)

	t.Run("domain with port", func(t *testing.T) {
		attr := TargetLogAttr(net.JoinHostPort(sentinelDomain, sentinelPort))
		if attr.Key != "domain" || attr.Value.String() != sentinelDomain {
			t.Errorf("expected domain=%s, got key=%s val=%s", sentinelDomain, attr.Key, attr.Value.String())
		}
		// Invariant: port must never be logged
		if strings.Contains(attr.Value.String(), sentinelPort) {
			t.Errorf("privacy violation: port %s found in log attribute", sentinelPort)
		}
	})

	t.Run("IPv4 literal with port", func(t *testing.T) {
		attr := TargetLogAttr(net.JoinHostPort(sentinelIPv4, sentinelPort))
		if attr.Key != "target_type" || attr.Value.String() != "ip" {
			t.Errorf("expected target_type=ip, got key=%s val=%s", attr.Key, attr.Value.String())
		}
		// Invariant: literal IP and port must never be logged
		if strings.Contains(attr.Value.String(), sentinelIPv4) {
			t.Errorf("privacy violation: literal IP %s found in log attribute", sentinelIPv4)
		}
		if strings.Contains(attr.Value.String(), sentinelPort) {
			t.Errorf("privacy violation: port %s found in log attribute", sentinelPort)
		}
	})

	t.Run("IPv6 literal with port", func(t *testing.T) {
		attr := TargetLogAttr(net.JoinHostPort(sentinelIPv6, sentinelPort))
		if attr.Key != "target_type" || attr.Value.String() != "ip" {
			t.Errorf("expected target_type=ip, got key=%s val=%s", attr.Key, attr.Value.String())
		}
		// Invariant: literal IPv6 and port must never be logged
		if strings.Contains(attr.Value.String(), sentinelIPv6) {
			t.Errorf("privacy violation: literal IPv6 %s found in log attribute", sentinelIPv6)
		}
	})
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, "none"},
		{"context canceled", context.Canceled, "context_canceled"},
		{"context deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"connection refused text", errors.New("dial tcp 127.0.0.1:80: connect: connection refused"), "connection_refused"},
		{"unreachable text", errors.New("dial tcp 192.0.2.1:443: connect: network is unreachable"), "network_unreachable"},
		{"dns error text", errors.New("dial tcp: lookup target.invalid: no such host"), "dns_resolution_failed"},
		{"reset text", errors.New("read: connection reset by peer"), "connection_reset"},
		{"generic error", errors.New("something went wrong"), "network_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat := ClassifyError(tt.err)
			if cat != tt.expected {
				t.Errorf("ClassifyError(%v) = %q; expected %q", tt.err, cat, tt.expected)
			}
		})
	}
}

func TestSOCKS5LoggingPrivacySentinel(t *testing.T) {
	const (
		sentinelIPv4    = "198.51.100.99"
		sentinelPortNum = 59876
		sentinelSecret  = "SECRET_TOKEN_LEAK_TEST_123"
	)
	sentinelPortStr := fmt.Sprintf("%d", sentinelPortNum)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial tcp %s: connection refused (%s)", address, sentinelSecret)
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	br := bufio.NewReader(proxyConn)
	cfg := HandlerConfig{DialTimeout: 500 * time.Millisecond, IdleTimeout: 500 * time.Millisecond}
	go func() {
		_ = HandleSOCKS5(context.Background(), proxyConn, br, dialer, logger, cfg)
	}()

	// SOCKS5 greeting
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	greetingResp := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, greetingResp)

	// SOCKS5 connect to sentinel IPv4
	ip := net.ParseIP(sentinelIPv4).To4()
	req := []byte{
		0x05, 0x01, 0x00, 0x01,
		ip[0], ip[1], ip[2], ip[3],
		byte(sentinelPortNum >> 8), byte(sentinelPortNum & 0xFF),
	}
	_, _ = clientConn.Write(req)

	// Read rejection reply
	reply := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, reply)

	logOutput := logBuf.String()

	// Assertions verifying that sensitive sentinel information is NOT present in logs
	if strings.Contains(logOutput, sentinelIPv4) {
		t.Errorf("privacy violation: literal IP %s leaked in SOCKS5 logs: %s", sentinelIPv4, logOutput)
	}
	if strings.Contains(logOutput, sentinelPortStr) {
		t.Errorf("privacy violation: port %s leaked in SOCKS5 logs: %s", sentinelPortStr, logOutput)
	}
	if strings.Contains(logOutput, sentinelSecret) {
		t.Errorf("privacy violation: raw error payload %s leaked in SOCKS5 logs: %s", sentinelSecret, logOutput)
	}

	// Verify that useful error classification and target_type ARE logged
	if !strings.Contains(logOutput, "error_category=connection_refused") {
		t.Errorf("expected error_category=connection_refused in log output: %s", logOutput)
	}
	if !strings.Contains(logOutput, "target_type=ip") {
		t.Errorf("expected target_type=ip in log output: %s", logOutput)
	}
}

func TestHTTPConnectLoggingPrivacySentinel(t *testing.T) {
	const (
		sentinelDomain  = "internal-classified.example.org"
		sentinelPortStr = "48443"
		sentinelSecret  = "SECRET_COOKIE_DATA_ABC"
	)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial tcp %s: network is unreachable (%s)", address, sentinelSecret)
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	br := bufio.NewReader(proxyConn)
	cfg := HandlerConfig{DialTimeout: 500 * time.Millisecond, IdleTimeout: 500 * time.Millisecond}
	go func() {
		_ = HandleHTTPConnect(context.Background(), proxyConn, br, dialer, logger, cfg)
	}()

	targetAuthority := net.JoinHostPort(sentinelDomain, sentinelPortStr)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAuthority, targetAuthority)
	_, _ = clientConn.Write([]byte(connectReq))

	resp := make([]byte, 512)
	_, _ = clientConn.Read(resp)

	logOutput := logBuf.String()

	// Assertions verifying that port and raw error payload do not leak
	if strings.Contains(logOutput, sentinelPortStr) {
		t.Errorf("privacy violation: port %s leaked in HTTP CONNECT logs: %s", sentinelPortStr, logOutput)
	}
	if strings.Contains(logOutput, sentinelSecret) {
		t.Errorf("privacy violation: raw error payload %s leaked in HTTP CONNECT logs: %s", sentinelSecret, logOutput)
	}

	// Verify that domain is logged, but without port
	if !strings.Contains(logOutput, fmt.Sprintf("domain=%s", sentinelDomain)) {
		t.Errorf("expected domain=%s in log output: %s", sentinelDomain, logOutput)
	}
	if !strings.Contains(logOutput, "error_category=network_unreachable") {
		t.Errorf("expected error_category=network_unreachable in log output: %s", logOutput)
	}
}

package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeConnSOCKS5(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			s1, _ := net.Pipe()
			return s1, nil
		},
	}

	go func() {
		_ = ServeConn(context.Background(), proxyConn, dialer, logger, HandlerConfig{
			DialTimeout: 1 * time.Second,
			IdleTimeout: 1 * time.Second,
		})
	}()

	// Send SOCKS5 greeting
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, resp)
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("expected SOCKS5 greeting response, got %v", resp)
	}
}

func TestServeConnHTTPConnect(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			s1, _ := net.Pipe()
			return s1, nil
		},
	}

	go func() {
		_ = ServeConn(context.Background(), proxyConn, dialer, logger, HandlerConfig{
			DialTimeout: 1 * time.Second,
			IdleTimeout: 1 * time.Second,
		})
	}()

	// Send HTTP CONNECT
	_, _ = clientConn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"))
	resp := make([]byte, 1024)
	n, _ := clientConn.Read(resp)
	if !strings.Contains(string(resp[:n]), "200 Connection Established") {
		t.Fatalf("expected 200 Connection Established, got %q", string(resp[:n]))
	}
}

func TestServeConnUnrecognizedProtocol(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeConn(context.Background(), proxyConn, &mockDialer{}, logger, HandlerConfig{
			DialTimeout: 1 * time.Second,
			IdleTimeout: 1 * time.Second,
		})
	}()

	// Send unrecognized sentinel initial bytes
	sentinelBytes := []byte{0x7E, 0xA1, 0xB2, 0xC3}
	sentinelHex := "0x7e"
	_, _ = clientConn.Write(sentinelBytes)

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for unrecognized protocol byte, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognized protocol") {
		t.Errorf("expected unrecognized protocol error, got: %v", err)
	}

	// Privacy verification: assert that logs contain error_category but NOT initial_byte_hex, client_addr, or sentinel input
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "error_category=unrecognized_protocol") {
		t.Errorf("expected error_category=unrecognized_protocol in log output, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "initial_byte_hex") {
		t.Errorf("privacy violation: log output contains initial_byte_hex: %s", logOutput)
	}
	if strings.Contains(logOutput, "client_addr") {
		t.Errorf("privacy violation: log output contains client_addr: %s", logOutput)
	}
	if strings.Contains(strings.ToLower(logOutput), sentinelHex) {
		t.Errorf("privacy violation: log output contains sentinel input %s: %s", sentinelHex, logOutput)
	}
	if strings.Contains(logOutput, string(sentinelBytes)) {
		t.Errorf("privacy violation: log output contains raw sentinel bytes: %s", logOutput)
	}
}

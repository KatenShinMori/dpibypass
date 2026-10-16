package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
)

func TestHTTPForwardSuccess(t *testing.T) {
	serverClient, serverUpstream := net.Pipe()
	serverReceived := make(chan string, 1)

	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 1024)
		n, _ := serverUpstream.Read(buf)
		serverReceived <- string(buf[:n])
		_, _ = serverUpstream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"))
	}()

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "example.com:80" {
				t.Errorf("expected target example.com:80, got %s", address)
			}
			return serverClient, nil
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	reqLine := "GET http://example.com/index.html HTTP/1.1"

	go func() {
		cfg := HandlerConfig{
			DialTimeout: 1 * time.Second,
			IdleTimeout: 2 * time.Second,
		}
		_ = HandleHTTPForward(context.Background(), proxyConn, br, reqLine, dialer, logger, cfg)
	}()

	// Send remaining headers
	headers := "Host: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
	_, _ = clientConn.Write([]byte(headers))

	// Verify upstream received rewritten origin-form request
	upstreamReq := <-serverReceived
	if !strings.HasPrefix(upstreamReq, "GET /index.html HTTP/1.1\r\n") {
		t.Fatalf("expected rewritten request line 'GET /index.html HTTP/1.1', got %q", upstreamReq)
	}
	if strings.Contains(strings.ToLower(upstreamReq), "proxy-connection") {
		t.Errorf("Proxy-Connection header should have been stripped")
	}

	// Read response
	resp := make([]byte, 1024)
	n, err := clientConn.Read(resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !strings.Contains(string(resp[:n]), "200 OK") || !strings.Contains(string(resp[:n]), "HELLO") {
		t.Errorf("unexpected client response: %q", string(resp[:n]))
	}
}

func TestHTTPForwardHostTweakIntegration(t *testing.T) {
	serverReceived := make(chan string, 1)
	serverClient, serverUpstream := net.Pipe()
	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 2048)
		n, _ := serverUpstream.Read(buf)
		serverReceived <- string(buf[:n])
		_, _ = serverUpstream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"))
	}()

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return serverClient, nil
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	reqLine := "GET http://example.com/test HTTP/1.1"

	go func() {
		cfg := HandlerConfig{
			DialTimeout: 1 * time.Second,
			IdleTimeout: 2 * time.Second,
			DefaultProfile: config.ProfileConfig{
				Type:            "http-host-tweak",
				HostHeaderTweak: "lowercase",
			},
		}
		_ = HandleHTTPForward(context.Background(), proxyConn, br, reqLine, dialer, logger, cfg)
	}()

	headers := "Host: example.com\r\nAccept: text/plain\r\n\r\n"
	_, _ = clientConn.Write([]byte(headers))

	upstreamReq := <-serverReceived
	if !strings.Contains(upstreamReq, "host: example.com") {
		t.Fatalf("expected tweaked 'host: example.com', got:\n%s", upstreamReq)
	}
	if !strings.Contains(upstreamReq, "Accept: text/plain") {
		t.Fatalf("expected other headers preserved, got:\n%s", upstreamReq)
	}

	resp := make([]byte, 1024)
	n, _ := clientConn.Read(resp)
	if !strings.Contains(string(resp[:n]), "200 OK") {
		t.Fatalf("expected 200 OK response, got %s", string(resp[:n]))
	}
}

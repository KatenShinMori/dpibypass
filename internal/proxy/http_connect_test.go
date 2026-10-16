package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

var defaultTestHandlerCfg = HandlerConfig{
	DialTimeout:              1 * time.Second,
	IdleTimeout:              2 * time.Second,
	InitialInspectionTimeout: 100 * time.Millisecond,
	MaxInitialBytes:          65536,
}

func TestHTTPConnectSuccess(t *testing.T) {
	serverReceived := make(chan []byte, 1)
	serverClient, serverUpstream := net.Pipe()
	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 12)
		_, _ = io.ReadFull(serverUpstream, buf)
		serverReceived <- buf
		_, _ = serverUpstream.Write([]byte("ECHO_PAYLOAD"))
	}()

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "example.com:443" {
				t.Errorf("unexpected target address %s", address)
			}
			return serverClient, nil
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	go func() {
		_ = HandleHTTPConnect(context.Background(), proxyConn, br, dialer, logger, defaultTestHandlerCfg)
	}()

	// Send CONNECT request
	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n"
	if _, err := clientConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("failed to write CONNECT request: %v", err)
	}

	// Read response: expect "HTTP/1.1 200 Connection Established\r\n\r\n"
	clientReader := bufio.NewReader(clientConn)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200 Connection Established") {
		t.Fatalf("expected 200 Connection Established, got %q", statusLine)
	}
	// Consume empty line after headers
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send application payload
	if _, err := clientConn.Write([]byte("CLIENT_HELLO")); err != nil {
		t.Fatalf("failed to write app payload: %v", err)
	}

	recv := <-serverReceived
	if string(recv) != "CLIENT_HELLO" {
		t.Fatalf("server received %q, expected 'CLIENT_HELLO'", string(recv))
	}

	// Read echo response
	echoBuf := make([]byte, 12)
	if _, err := io.ReadFull(clientReader, echoBuf); err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}
	if string(echoBuf) != "ECHO_PAYLOAD" {
		t.Fatalf("client received %q, expected 'ECHO_PAYLOAD'", string(echoBuf))
	}
}

func TestHTTPConnectPipelinedBufferedBytes(t *testing.T) {
	// Tests that when client writes CONNECT headers + initial client payload in a SINGLE packet/write,
	// the initial client payload is NOT lost by the HTTP header reader and is forwarded upstream.
	serverReceived := make(chan []byte, 1)
	serverClient, serverUpstream := net.Pipe()
	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 16)
		_, _ = io.ReadFull(serverUpstream, buf)
		serverReceived <- buf
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

	go func() {
		_ = HandleHTTPConnect(context.Background(), proxyConn, br, dialer, logger, defaultTestHandlerCfg)
	}()

	// Combined write: CONNECT request followed immediately by 16 bytes of binary/TLS data
	combined := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nPIPELINED_DATA!!")
	if _, err := clientConn.Write(combined); err != nil {
		t.Fatalf("failed to send combined payload: %v", err)
	}

	// Read 200 Connection Established
	clientReader := bufio.NewReader(clientConn)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200, got line %q, err %v", statusLine, err)
	}

	recv := <-serverReceived
	if string(recv) != "PIPELINED_DATA!!" {
		t.Fatalf("pipelined bytes lost or corrupted! Got %q, expected 'PIPELINED_DATA!!'", string(recv))
	}
}

func TestHTTPConnectDialFailure(t *testing.T) {
	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("upstream connection refused")
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	go func() {
		_ = HandleHTTPConnect(context.Background(), proxyConn, br, dialer, logger, defaultTestHandlerCfg)
	}()

	_, _ = clientConn.Write([]byte("CONNECT unreachable.local:443 HTTP/1.1\r\n\r\n"))

	resp := make([]byte, 1024)
	n, _ := clientConn.Read(resp)
	respStr := string(resp[:n])
	if !strings.Contains(respStr, "502 Bad Gateway") {
		t.Fatalf("expected 502 Bad Gateway on dial failure, got %q", respStr)
	}
}

func TestHTTPConnectMalformed(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		expectCode string
	}{
		{"missing port", "CONNECT example.com HTTP/1.1\r\n\r\n", "400"},
		{"invalid method", "POST / HTTP/1.1\r\n\r\n", "405"},
		{"malformed request line", "INVALID\r\n\r\n", "400"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, proxyConn := net.Pipe()
			defer clientConn.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			br := bufio.NewReader(proxyConn)

			go func() {
				_ = HandleHTTPConnect(context.Background(), proxyConn, br, &mockDialer{}, logger, defaultTestHandlerCfg)
			}()

			_, _ = clientConn.Write([]byte(tt.request))

			resp := make([]byte, 512)
			n, _ := clientConn.Read(resp)
			respStr := string(resp[:n])
			if !strings.Contains(respStr, tt.expectCode) {
				t.Errorf("for %q, expected status %s, got %q", tt.name, tt.expectCode, respStr)
			}
		})
	}
}

func TestHTTPConnectHeaderTooLarge(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	go func() {
		_ = HandleHTTPConnect(context.Background(), proxyConn, br, &mockDialer{}, logger, defaultTestHandlerCfg)
	}()

	// Send huge header line exceeding 16 KB
	hugeReq := bytes.Buffer{}
	hugeReq.WriteString("CONNECT example.com:443 HTTP/1.1\r\nX-Huge: ")
	hugeReq.Write(bytes.Repeat([]byte("A"), 20*1024))
	hugeReq.WriteString("\r\n\r\n")

	go func() {
		_, _ = clientConn.Write(hugeReq.Bytes())
	}()

	resp := make([]byte, 512)
	n, _ := clientConn.Read(resp)
	respStr := string(resp[:n])
	if !strings.Contains(respStr, "400") && !strings.Contains(respStr, "431") {
		t.Errorf("expected 400 or 431 for huge headers, got %q", respStr)
	}
}

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// mockDialer allows mocking upstream connections in tests.
type mockDialer struct {
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.dialFunc(ctx, network, address)
}

func TestSOCKS5ConnectSuccess(t *testing.T) {
	// Mock target server
	serverReceived := make(chan []byte, 1)
	serverClient, serverUpstream := net.Pipe()
	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 11)
		_, _ = io.ReadFull(serverUpstream, buf)
		serverReceived <- buf
		_, _ = serverUpstream.Write([]byte("SERVER_ECHO"))
	}()

	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "127.0.0.1:8080" {
				t.Errorf("unexpected target address %s", address)
			}
			return serverClient, nil
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	defaultSOCKS5TestCfg := HandlerConfig{
		DialTimeout:              1 * time.Second,
		IdleTimeout:              2 * time.Second,
		InitialInspectionTimeout: 100 * time.Millisecond,
		MaxInitialBytes:          65536,
	}

	proxyErrCh := make(chan error, 1)
	go func() {
		proxyErrCh <- HandleSOCKS5(context.Background(), proxyConn, br, dialer, logger, defaultSOCKS5TestCfg)
	}()

	// 1. Client sends greeting: VER=0x05, NMETHODS=1, METHODS=[0x00]
	if _, err := clientConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("failed to send SOCKS5 greeting: %v", err)
	}

	// 2. Read greeting response: expect [0x05, 0x00]
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, greetingResp); err != nil {
		t.Fatalf("failed to read greeting response: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("unexpected greeting response: %v", greetingResp)
	}

	// 3. Send CONNECT request for 127.0.0.1:8080
	req := []byte{
		0x05,         // VER
		0x01,         // CMD: CONNECT
		0x00,         // RSV
		0x01,         // ATYP: IPv4
		127, 0, 0, 1, // 127.0.0.1
		0x1F, 0x90, // Port 8080
	}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("failed to send CONNECT request: %v", err)
	}

	// 4. Read CONNECT response: expect [0x05, 0x00, 0x00, 0x01, ...]
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, connResp); err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	if connResp[1] != 0x00 {
		t.Fatalf("CONNECT failed with status 0x%02x", connResp[1])
	}

	// 5. Send application data
	if _, err := clientConn.Write([]byte("HELLO_SOCKS")); err != nil {
		t.Fatalf("failed to send app data: %v", err)
	}

	receivedAtServer := <-serverReceived
	if string(receivedAtServer) != "HELLO_SOCKS" {
		t.Fatalf("server received %q, expected 'HELLO_SOCKS'", string(receivedAtServer))
	}

	// 6. Read server echo
	echoResp := make([]byte, 11)
	if _, err := io.ReadFull(clientConn, echoResp); err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}
	if string(echoResp) != "SERVER_ECHO" {
		t.Fatalf("client received echo %q, expected 'SERVER_ECHO'", string(echoResp))
	}
}

func TestSOCKS5ConnectDomain(t *testing.T) {
	serverClient, serverUpstream := net.Pipe()
	defer serverUpstream.Close()

	var dialedAddr string
	dialer := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedAddr = address
			return serverClient, nil
		},
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	go func() {
		cfg := HandlerConfig{DialTimeout: 1 * time.Second, IdleTimeout: 2 * time.Second}
		_ = HandleSOCKS5(context.Background(), proxyConn, br, dialer, logger, cfg)
	}()

	// Greeting
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	greetingResp := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, greetingResp)

	// Domain name request: "example.com", port 443
	domain := "example.com"
	req := bytes.Buffer{}
	req.Write([]byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))})
	req.WriteString(domain)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 443)
	req.Write(portBuf)

	_, _ = clientConn.Write(req.Bytes())

	connResp := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, connResp)
	if connResp[1] != 0x00 {
		t.Fatalf("expected success reply, got 0x%02x", connResp[1])
	}

	if dialedAddr != "example.com:443" {
		t.Errorf("expected dial to example.com:443, got %s", dialedAddr)
	}
}

func TestSOCKS5UnsupportedCommand(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	errCh := make(chan error, 1)
	go func() {
		cfg := HandlerConfig{DialTimeout: 1 * time.Second, IdleTimeout: 2 * time.Second}
		errCh <- HandleSOCKS5(context.Background(), proxyConn, br, &mockDialer{}, logger, cfg)
	}()

	// Greeting
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, resp)

	// Send UDP ASSOCIATE command (CMD=0x03)
	req := []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	_, _ = clientConn.Write(req)

	connResp := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, connResp)
	if connResp[1] != 0x07 { // 0x07 = Command not supported
		t.Errorf("expected reply code 0x07 (Command not supported), got 0x%02x", connResp[1])
	}

	err := <-errCh
	if err == nil {
		t.Error("expected error for unsupported command, got nil")
	}
}

func TestSOCKS5UnsupportedAuth(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	br := bufio.NewReader(proxyConn)

	go func() {
		cfg := HandlerConfig{DialTimeout: 1 * time.Second, IdleTimeout: 2 * time.Second}
		_ = HandleSOCKS5(context.Background(), proxyConn, br, &mockDialer{}, logger, cfg)
	}()

	// Client offers only GSSAPI (0x01) and Username/Password (0x02), but not 0x00 (No Auth)
	_, _ = clientConn.Write([]byte{0x05, 0x02, 0x01, 0x02})

	resp := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, resp)
	if resp[1] != 0xFF { // 0xFF = No acceptable methods
		t.Errorf("expected 0xFF (No Acceptable Methods), got 0x%02x", resp[1])
	}
}

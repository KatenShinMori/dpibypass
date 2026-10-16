package app

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/logging"
)

type mockAppDialer struct {
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockAppDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.dialFunc(ctx, network, address)
}

func TestAppLifecycleAndProxying(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0" // ephemeral port for test

	buf := &bytes.Buffer{}
	logger, err := logging.New("info", buf)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	application, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create application: %v", err)
	}

	// Mock target server
	serverClient, serverUpstream := net.Pipe()
	go func() {
		defer serverUpstream.Close()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(serverUpstream, buf)
		_, _ = serverUpstream.Write([]byte("PONG!"))
	}()

	mockD := &mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return serverClient, nil
		},
	}
	application.SetDialer(mockD)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- application.Run(ctx)
	}()

	// Wait for listener to bind
	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if addr == "" {
		cancel()
		t.Fatal("listener did not start within timeout")
	}

	// 1. Test HTTP CONNECT through the app listener
	clientConn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("failed to connect to app listener: %v", err)
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("CONNECT target.com:443 HTTP/1.1\r\n\r\n"))
	r := bufio.NewReader(clientConn)
	status, err := r.ReadString('\n')
	if err != nil || !strings.Contains(status, "200 Connection Established") {
		cancel()
		t.Fatalf("expected 200 Connection Established, got %q, err %v", status, err)
	}
	// read empty line
	_, _ = r.ReadString('\n')

	// Send data through tunnel
	_, _ = clientConn.Write([]byte("PING!"))
	resp := make([]byte, 5)
	_, _ = io.ReadFull(r, resp)
	if string(resp) != "PONG!" {
		cancel()
		t.Fatalf("expected PONG!, got %q", string(resp))
	}
	_ = clientConn.Close()

	// 2. Cancel context to initiate graceful shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("app.Run exited with unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("app did not shut down within 2 seconds")
	}
}

func TestAppConnectionLimitEnforcement(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Limits.MaxConnections = 1 // Limit to 1 connection

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	// Block upstream so connection stays open
	serverClient, serverUpstream := net.Pipe()
	defer serverUpstream.Close()

	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			return serverClient, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = application.Run(ctx)
	}()

	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connection 1 (should be accepted)
	c1, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("conn 1 dial failed: %v", err)
	}
	defer c1.Close()

	// Wait briefly for c1 to be accounted for
	time.Sleep(50 * time.Millisecond)

	// Connection 2 (exceeds limit 1, should be rejected / closed)
	c2, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("conn 2 dial failed: %v", err)
	}
	defer c2.Close()

	// Reading from c2 should immediately encounter EOF or closed
	buf2 := make([]byte, 10)
	_, readErr := c2.Read(buf2)
	if readErr == nil {
		t.Fatal("expected connection 2 to be closed immediately due to limit")
	}
}

func TestAppNilConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)

	if _, err := New(nil, logger); err == nil {
		t.Fatal("expected error for nil config, got nil")
	}

	cfg := config.DefaultConfig()
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("expected error for nil logger, got nil")
	}
}

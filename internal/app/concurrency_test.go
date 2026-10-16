package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/logging"
)

func TestAppHighConcurrency(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Limits.MaxConnections = 200
	cfg.Timeouts.ShutdownGraceMS = 1000

	buf := &bytes.Buffer{}
	logger, err := logging.New("info", buf)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	application, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create application: %v", err)
	}

	// Mock upstream dialer that echoes received data back to client and closes
	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			clientEnd, serverEnd := net.Pipe()
			go func() {
				defer serverEnd.Close()
				buf := make([]byte, 2048)
				if _, err := io.ReadFull(serverEnd, buf); err == nil {
					_, _ = serverEnd.Write(buf)
				}
			}()
			return clientEnd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Run(ctx)
	}()

	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("listener did not start within timeout")
	}

	const concurrency = 50
	const payloadSize = 2048

	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errs <- fmt.Errorf("worker %d dial failed: %w", workerID, err)
				return
			}
			defer conn.Close()

			// Perform HTTP CONNECT tunnel request
			req := fmt.Sprintf("CONNECT host-%d.internal:443 HTTP/1.1\r\n\r\n", workerID)
			if _, err := conn.Write([]byte(req)); err != nil {
				errs <- fmt.Errorf("worker %d write CONNECT: %w", workerID, err)
				return
			}

			r := bufio.NewReader(conn)
			status, err := r.ReadString('\n')
			if err != nil || !strings.Contains(status, "200 Connection Established") {
				errs <- fmt.Errorf("worker %d unexpected status %q, err %v", workerID, status, err)
				return
			}
			// Read trailing empty header line
			_, _ = r.ReadString('\n')

			// Transmit random payload and verify echo
			payload := make([]byte, payloadSize)
			_, _ = rand.Read(payload)
			expectedHash := sha256.Sum256(payload)

			if _, err := conn.Write(payload); err != nil {
				errs <- fmt.Errorf("worker %d write payload: %w", workerID, err)
				return
			}

			echoed := make([]byte, payloadSize)
			if _, err := io.ReadFull(r, echoed); err != nil {
				errs <- fmt.Errorf("worker %d read echo: %w", workerID, err)
				return
			}

			if sha256.Sum256(echoed) != expectedHash {
				errs <- fmt.Errorf("worker %d payload corrupted in transit", workerID)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrency error: %v", err)
	}

	// Verify active connection counter returns to 0
	deadline := time.Now().Add(2 * time.Second)
	for application.ActiveConnections() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if active := application.ActiveConnections(); active != 0 {
		t.Errorf("expected 0 active connections after workers finished, got %d", active)
	}

	cancel()
	<-errCh
}

func TestAppConnectionLimitEnforcementBurst(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Limits.MaxConnections = 10
	cfg.Timeouts.ShutdownGraceMS = 500

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	// Mock upstream that holds connections open
	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, s := net.Pipe()
			go func() {
				defer s.Close()
				<-ctx.Done()
			}()
			return c, nil
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

	const attempts = 30
	var conns []net.Conn
	var mu sync.Mutex
	var acceptedCount int
	var rejectedCount int
	var wg sync.WaitGroup

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				return
			}

			// Try writing greeting to verify if connection is admitted or immediately closed
			_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			_, err = c.Write([]byte("CONNECT target.com:443 HTTP/1.1\r\n\r\n"))
			if err != nil {
				_ = c.Close()
				mu.Lock()
				rejectedCount++
				mu.Unlock()
				return
			}

			// Read response
			resp := make([]byte, 128)
			n, readErr := c.Read(resp)
			if readErr != nil || n == 0 {
				_ = c.Close()
				mu.Lock()
				rejectedCount++
				mu.Unlock()
				return
			}

			mu.Lock()
			acceptedCount++
			conns = append(conns, c)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Ensure limit was strictly enforced
	if acceptedCount > cfg.Limits.MaxConnections {
		t.Errorf("admitted %d connections, exceeding configured limit %d", acceptedCount, cfg.Limits.MaxConnections)
	}
	if rejectedCount == 0 {
		t.Error("expected burst connections to be rejected once limit was reached")
	}

	// Clean up admitted connections
	for _, c := range conns {
		_ = c.Close()
	}
}

func TestAppGracefulShutdownDraining(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Timeouts.ShutdownGraceMS = 2000

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	// Mock server that waits before completing transfer
	serverDone := make(chan struct{})
	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			clientEnd, serverEnd := net.Pipe()
			go func() {
				defer serverEnd.Close()
				buf := make([]byte, 4)
				_, _ = io.ReadFull(serverEnd, buf)
				// Wait for signal before sending reply
				<-serverDone
				_, _ = serverEnd.Write([]byte("SLOW_PONG"))
			}()
			return clientEnd, nil
		},
	})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(runCtx)
	}()

	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 1. Establish an active in-flight connection
	inFlightConn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial in-flight connection: %v", err)
	}
	defer inFlightConn.Close()

	_, _ = inFlightConn.Write([]byte("CONNECT target.com:443 HTTP/1.1\r\n\r\n"))
	r := bufio.NewReader(inFlightConn)
	status, err := r.ReadString('\n')
	if err != nil || !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("unexpected tunnel status %q, err %v", status, err)
	}
	_, _ = r.ReadString('\n')

	// Send initial client request
	_, _ = inFlightConn.Write([]byte("PING"))

	// 2. Initiate shutdown while connection is still active and waiting for server response
	sCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer sCancel()
	shutdownErrCh := make(chan error, 1)
	go func() {
		shutdownErrCh <- application.Shutdown(sCtx)
	}()

	// 3. Verify that NEW connections are refused after shutdown initiated
	var dialErr error
	for i := 0; i < 20; i++ {
		var newConn net.Conn
		newConn, dialErr = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = newConn.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if dialErr == nil {
		t.Error("expected new connection to be refused after shutdown initiated")
	}

	// 4. Release server to send response to in-flight connection
	close(serverDone)

	resp := make([]byte, 9)
	if _, err := io.ReadFull(r, resp); err != nil {
		t.Fatalf("in-flight connection was severed prematurely during draining: %v", err)
	}
	if string(resp) != "SLOW_PONG" {
		t.Fatalf("expected response 'SLOW_PONG', got %q", string(resp))
	}
	_ = inFlightConn.Close()

	// 5. Verify Run completes cleanly
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("Run exited with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within timeout")
	}
}

func TestAppGracefulShutdownTimeoutForceClose(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Timeouts.ShutdownGraceMS = 200 // Short grace timeout (200ms)

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	// Mock server that hangs forever
	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			clientEnd, serverEnd := net.Pipe()
			go func() {
				defer serverEnd.Close()
				<-ctx.Done()
			}()
			return clientEnd, nil
		},
	})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(runCtx)
	}()

	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connect client and hold connection completely idle / uncompleted
	hangingConn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial hanging connection: %v", err)
	}
	defer hangingConn.Close()

	_, _ = hangingConn.Write([]byte("CONNECT target.com:443 HTTP/1.1\r\n\r\n"))
	r := bufio.NewReader(hangingConn)
	_, _ = r.ReadString('\n')
	_, _ = r.ReadString('\n')

	// Initiate shutdown
	start := time.Now()
	runCancel()

	// Run should forcefully abort the connection after ~200ms and exit cleanly
	select {
	case err := <-runErrCh:
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Run exited with error: %v", err)
		}
		if elapsed > 1500*time.Millisecond {
			t.Errorf("shutdown took %v, expected force close near 200ms grace period", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run failed to forcefully abort hanging connection within 2 seconds")
	}
}

func TestAppGoroutineLeakCheck(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Timeouts.ShutdownGraceMS = 300
	cfg.Timeouts.InitialInspectionMS = 100
	cfg.Timeouts.IdleS = 1

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	application.SetDialer(&mockAppDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, s := net.Pipe()
			go func() {
				defer s.Close()
				b := make([]byte, 4)
				if _, err := io.ReadFull(s, b); err == nil {
					_, _ = s.Write(b)
				}
			}()
			return c, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run(ctx)
	}()

	var addr string
	for i := 0; i < 50; i++ {
		addr = application.Addr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Warmup connection
	if c, err := net.Dial("tcp", addr); err == nil {
		_ = c.Close()
	}
	time.Sleep(50 * time.Millisecond)

	// Record baseline goroutine count
	baseGoroutines := runtime.NumGoroutine()

	// Run repeated connection cycles with different lifecycle outcomes
	for i := 0; i < 5; i++ {
		// 1. Normal HTTP CONNECT
		c1, err := net.Dial("tcp", addr)
		if err == nil {
			_, _ = c1.Write([]byte("CONNECT echo.internal:443 HTTP/1.1\r\n\r\n"))
			r := bufio.NewReader(c1)
			_, _ = r.ReadString('\n')
			_, _ = r.ReadString('\n')
			_, _ = c1.Write([]byte("DATA"))
			resp := make([]byte, 4)
			_, _ = io.ReadFull(r, resp)
			_ = c1.Close()
		}

		// 2. Immediate client disconnect (aborted handshake)
		c2, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c2.Close()
		}

		// 3. Malformed initial byte
		c3, err := net.Dial("tcp", addr)
		if err == nil {
			_, _ = c3.Write([]byte{0xFF})
			buf := make([]byte, 10)
			_, _ = c3.Read(buf)
			_ = c3.Close()
		}
	}

	// Verify all connections are tracked as closed
	deadline := time.Now().Add(2 * time.Second)
	for application.ActiveConnections() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if active := application.ActiveConnections(); active != 0 {
		t.Fatalf("expected 0 active connections, got %d", active)
	}

	// Allow goroutines a bounded settling window
	var currentGoroutines int
	settled := false
	for i := 0; i < 50; i++ {
		runtime.Gosched()
		currentGoroutines = runtime.NumGoroutine()
		// Allow a reasonable tolerance (+3) for runtime background workers
		if currentGoroutines <= baseGoroutines+3 {
			settled = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !settled {
		t.Errorf("potential goroutine leak: baseline=%d, current=%d (difference %d)",
			baseGoroutines, currentGoroutines, currentGoroutines-baseGoroutines)
	}

	cancel()
	<-runErrCh
}

func TestAppConcurrentShutdown(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Timeouts.ShutdownGraceMS = 500

	buf := &bytes.Buffer{}
	logger, _ := logging.New("info", buf)
	application, _ := New(cfg, logger)

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	go func() {
		_ = application.Run(runCtx)
	}()

	for i := 0; i < 50; i++ {
		if application.Addr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Call Shutdown concurrently from 10 goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sCtx, sCancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer sCancel()
			_ = application.Shutdown(sCtx)
		}()
	}

	wg.Wait()
}

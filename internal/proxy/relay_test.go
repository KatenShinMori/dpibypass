package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"
)

func TestBidirectionalRelayDataIntegrity(t *testing.T) {
	// Create two in-memory pipe pairs representing client <-> proxy <-> server
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, serverConn := net.Pipe()

	dataSize := 256 * 1024 // 256 KB
	payload := make([]byte, dataSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate random payload: %v", err)
	}
	expectedHash := sha256.Sum256(payload)

	initialBuffered := []byte("PRE_BUFFERED_DATA_")

	// Server goroutine: reads initialBuffered + payload, writes back response
	serverErrCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		buf := &bytes.Buffer{}
		_, err := io.CopyN(buf, serverConn, int64(len(initialBuffered)+len(payload)))
		if err != nil {
			serverErrCh <- err
			return
		}
		// Echo received data back
		_, err = serverConn.Write(buf.Bytes())
		serverErrCh <- err
	}()

	// Proxy relay in goroutine
	relayErrCh := make(chan error, 1)
	go func() {
		err := BidirectionalRelay(context.Background(), proxyClientConn, proxyUpstreamConn, initialBuffered, RelayConfig{
			BufferSize:  8192,
			IdleTimeout: 5 * time.Second,
		})
		relayErrCh <- err
	}()

	// Client writes payload and reads echo
	clientErrCh := make(chan error, 1)
	receivedEcho := &bytes.Buffer{}
	go func() {
		defer clientConn.Close()
		if _, err := clientConn.Write(payload); err != nil {
			clientErrCh <- err
			return
		}
		expectedTotal := int64(len(initialBuffered) + len(payload))
		_, err := io.CopyN(receivedEcho, clientConn, expectedTotal)
		clientErrCh <- err
	}()

	// Await completion
	if err := <-clientErrCh; err != nil {
		t.Fatalf("client error: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
	<-relayErrCh // Relay may return nil or clean EOF

	receivedBytes := receivedEcho.Bytes()
	if !bytes.HasPrefix(receivedBytes, initialBuffered) {
		t.Errorf("expected initial buffered prefix %q, got prefix %q", initialBuffered, receivedBytes[:len(initialBuffered)])
	}

	actualPayload := receivedBytes[len(initialBuffered):]
	actualHash := sha256.Sum256(actualPayload)
	if actualHash != expectedHash {
		t.Errorf("payload corrupted in transit! Hash mismatch: expected %x, got %x", expectedHash, actualHash)
	}
}

func TestRelayIdleTimeout(t *testing.T) {
	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	relayErrCh := make(chan error, 1)
	go func() {
		err := BidirectionalRelay(context.Background(), proxyClientConn, proxyUpstreamConn, nil, RelayConfig{
			IdleTimeout: 100 * time.Millisecond,
		})
		relayErrCh <- err
	}()

	// Do not send any data; relay should time out
	select {
	case err := <-relayErrCh:
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("relay did not enforce idle timeout within 1s")
	}
}

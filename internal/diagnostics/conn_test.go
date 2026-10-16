package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"dpibypass/internal/strategy"
	"dpibypass/internal/tlsparse"
)

// recordingMockConn records all Write calls and allows injecting write errors.
type recordingMockConn struct {
	writes   [][]byte
	writeErr error
	closed   bool
}

func (r *recordingMockConn) Read(b []byte) (int, error) { return 0, io.EOF }
func (r *recordingMockConn) Close() error               { r.closed = true; return nil }
func (r *recordingMockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (r *recordingMockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (r *recordingMockConn) SetDeadline(t time.Time) error      { return nil }
func (r *recordingMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *recordingMockConn) SetWriteDeadline(t time.Time) error { return nil }

func (r *recordingMockConn) Write(b []byte) (int, error) {
	if r.writeErr != nil {
		return 0, r.writeErr
	}
	chunk := make([]byte, len(b))
	copy(chunk, b)
	r.writes = append(r.writes, chunk)
	return len(b), nil
}

func (r *recordingMockConn) ConcatenatedBytes() []byte {
	return bytes.Join(r.writes, nil)
}

// buildTestClientHello creates a minimal valid TLS ClientHello with the given SNI.
func buildTestClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniEntryLen := 1 + 2 + len(sniBytes)
	sniExtLen := 2 + sniEntryLen
	extTotalLen := 2 + 2 + sniExtLen

	handshakeBody := []byte{0x03, 0x03}
	random := make([]byte, 32)
	handshakeBody = append(handshakeBody, random...)
	handshakeBody = append(handshakeBody, 0x00)
	handshakeBody = append(handshakeBody, 0x00, 0x02, 0x13, 0x01)
	handshakeBody = append(handshakeBody, 0x01, 0x00)

	extVec := []byte{
		byte(extTotalLen >> 8), byte(extTotalLen),
		0x00, 0x00,
		byte(sniExtLen >> 8), byte(sniExtLen),
		byte(sniEntryLen >> 8), byte(sniEntryLen),
		0x00,
		byte(len(sniBytes) >> 8), byte(len(sniBytes)),
	}
	extVec = append(extVec, sniBytes...)
	handshakeBody = append(handshakeBody, extVec...)

	handshakeMsgLen := len(handshakeBody)
	handshakeHeader := []byte{
		0x01,
		byte(handshakeMsgLen >> 16), byte(handshakeMsgLen >> 8), byte(handshakeMsgLen),
	}
	fullHandshake := append(handshakeHeader, handshakeBody...)

	recordLen := len(fullHandshake)
	recordHeader := []byte{
		0x16,
		0x03, 0x01,
		byte(recordLen >> 8), byte(recordLen),
	}
	return append(recordHeader, fullHandshake...)
}

func TestStrategyConnTCPWriteSplit(t *testing.T) {
	mock := &recordingMockConn{}
	strat := strategy.NewTCPWriteSplitStrategy("sni-mid", 0)
	conn := NewStrategyConn(context.Background(), mock, strat)

	clientHello := buildTestClientHello("test.example.com")
	n, err := conn.Write(clientHello)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(clientHello) {
		t.Fatalf("expected written %d bytes, got %d", len(clientHello), n)
	}

	if !conn.Applied() {
		t.Fatal("expected conn.Applied() == true for successful write split")
	}
	if conn.IsFallback() {
		t.Fatal("expected conn.IsFallback() == false")
	}
	if conn.ChunkCount() != 2 {
		t.Fatalf("expected 2 write chunks, got %d", conn.ChunkCount())
	}
	if len(mock.writes) != 2 {
		t.Fatalf("expected 2 socket writes, got %d", len(mock.writes))
	}

	// Verify byte stream preservation
	if !bytes.Equal(mock.ConcatenatedBytes(), clientHello) {
		t.Fatal("concatenated socket writes do not match original ClientHello bytes")
	}

	// Subsequent write passes through directly
	secondData := []byte("APPLICATION_DATA")
	_, err = conn.Write(secondData)
	if err != nil {
		t.Fatalf("second write error: %v", err)
	}
	if len(mock.writes) != 3 {
		t.Fatalf("expected 3 total writes after passthrough, got %d", len(mock.writes))
	}
	if !bytes.Equal(mock.writes[2], secondData) {
		t.Fatal("second write data mismatch")
	}
}

func TestStrategyConnTLSRecordSplit(t *testing.T) {
	mock := &recordingMockConn{}
	strat := strategy.NewTLSRecordSplitStrategy("sni-mid")
	conn := NewStrategyConn(context.Background(), mock, strat)

	clientHello := buildTestClientHello("split.target.org")
	n, err := conn.Write(clientHello)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(clientHello) {
		t.Fatalf("expected written %d bytes returned to client, got %d", len(clientHello), n)
	}

	if !conn.Applied() {
		t.Fatal("expected conn.Applied() == true")
	}

	// Reparse emitted bytes to verify valid 2-record TLS structure
	reparsed := tlsparse.ParseClientHello(mock.ConcatenatedBytes(), tlsparse.DefaultLimits())
	if reparsed.Status != tlsparse.StatusParsed {
		t.Fatalf("reparse failed: %s", reparsed.Status)
	}
	if !reparsed.Metadata.IsFragmented {
		t.Fatal("expected fragmented metadata in output")
	}
}

func TestStrategyConnCompositeRecordThenWriteSplit(t *testing.T) {
	mock := &recordingMockConn{}
	strat := strategy.NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0)
	conn := NewStrategyConn(context.Background(), mock, strat)

	clientHello := buildTestClientHello("composite.test.net")
	n, err := conn.Write(clientHello)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(clientHello) {
		t.Fatalf("expected written %d bytes, got %d", len(clientHello), n)
	}

	if !conn.Applied() {
		t.Fatal("expected conn.Applied() == true")
	}
	if conn.ChunkCount() != 2 {
		t.Fatalf("expected 2 write chunks, got %d", conn.ChunkCount())
	}
}

func TestStrategyConnNoneStrategy(t *testing.T) {
	mock := &recordingMockConn{}
	strat := strategy.NewNoneStrategy()
	conn := NewStrategyConn(context.Background(), mock, strat)

	data := []byte("SAMPLE_TLS_OR_HTTP_DATA")
	n, err := conn.Write(data)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes, got %d", len(data), n)
	}

	// For none baseline, Applied must be false (no transformation)
	if conn.Applied() {
		t.Fatal("expected Applied() == false for baseline 'none'")
	}
	if conn.IsFallback() {
		t.Fatal("expected IsFallback() == false for baseline 'none'")
	}
	if len(mock.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(mock.writes))
	}
}

func TestStrategyConnNonTLSInput(t *testing.T) {
	mock := &recordingMockConn{}
	strat := strategy.NewTCPWriteSplitStrategy("sni-mid", 0)
	conn := NewStrategyConn(context.Background(), mock, strat)

	nonTLS := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err := conn.Write(nonTLS)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(nonTLS) {
		t.Fatalf("expected %d bytes, got %d", len(nonTLS), n)
	}

	// Non-TLS must NOT claim strategy applied
	if conn.Applied() {
		t.Fatal("expected Applied() == false for non-TLS input")
	}
	if !conn.IsFallback() {
		t.Fatal("expected IsFallback() == true for non-TLS input")
	}
	if len(mock.writes) != 1 {
		t.Fatalf("expected 1 write chunk for unfragmented fallback, got %d", len(mock.writes))
	}
	if !bytes.Equal(mock.writes[0], nonTLS) {
		t.Fatal("data forwarded differs from original")
	}
}

func TestStrategyConnWriteErrorPropagation(t *testing.T) {
	injectedErr := errors.New("socket connection dropped")
	mock := &recordingMockConn{writeErr: injectedErr}
	strat := strategy.NewTCPWriteSplitStrategy("sni-mid", 0)
	conn := NewStrategyConn(context.Background(), mock, strat)

	clientHello := buildTestClientHello("error.target.org")
	_, err := conn.Write(clientHello)
	if err == nil {
		t.Fatal("expected write error, got nil")
	}

	if conn.Applied() {
		t.Fatal("expected Applied() == false when socket write fails")
	}
}

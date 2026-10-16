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

	"dpibypass/internal/config"
)

// recordingConn is a mock in-memory net.Conn that captures all writes.
type recordingConn struct {
	writes [][]byte
}

func (r *recordingConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (r *recordingConn) Write(b []byte) (int, error) {
	chunk := make([]byte, len(b))
	copy(chunk, b)
	r.writes = append(r.writes, chunk)
	return len(b), nil
}

func (r *recordingConn) Close() error {
	return nil
}

func (r *recordingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (r *recordingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (r *recordingConn) SetDeadline(t time.Time) error {
	return nil
}

func (r *recordingConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (r *recordingConn) SetReadDeadline(t time.Time) error {
	return nil
}

// buildSyntheticClientHello creates a minimal, valid TLS ClientHello record with the specified SNI.
func buildSyntheticClientHello(sni string) []byte {
	// A minimal valid TLS 1.3/1.2 ClientHello
	sniBytes := []byte(sni)
	sniEntryLen := 1 + 2 + len(sniBytes) // type 0 (1B), len (2B), name
	sniExtLen := 2 + sniEntryLen         // list len (2B) + entry
	extTotalLen := 2 + 2 + sniExtLen     // ext type (2B) + ext len (2B) + sniExt

	handshakeBody := []byte{
		0x03, 0x03, // legacy_version TLS 1.2
	}
	random := make([]byte, 32)
	handshakeBody = append(handshakeBody, random...)
	handshakeBody = append(handshakeBody, 0x00)                   // session_id length 0
	handshakeBody = append(handshakeBody, 0x00, 0x02, 0x13, 0x01) // cipher suites (1 suite: TLS_AES_128_GCM_SHA256)
	handshakeBody = append(handshakeBody, 0x01, 0x00)             // compression methods (1 method: 0)

	// Extension vector
	extVec := []byte{
		byte(extTotalLen >> 8), byte(extTotalLen),
		0x00, 0x00, // ext type 0 (server_name)
		byte(sniExtLen >> 8), byte(sniExtLen),
		byte(sniEntryLen >> 8), byte(sniEntryLen),
		0x00, // host_name type 0
		byte(len(sniBytes) >> 8), byte(len(sniBytes)),
	}
	extVec = append(extVec, sniBytes...)
	handshakeBody = append(handshakeBody, extVec...)

	handshakeMsgLen := len(handshakeBody)
	handshakeHeader := []byte{
		0x01, // HandshakeType ClientHello
		byte(handshakeMsgLen >> 16), byte(handshakeMsgLen >> 8), byte(handshakeMsgLen),
	}
	fullHandshake := append(handshakeHeader, handshakeBody...)

	recordLen := len(fullHandshake)
	recordHeader := []byte{
		0x16,       // ContentType Handshake
		0x03, 0x01, // LegacyRecordVersion TLS 1.0
		byte(recordLen >> 8), byte(recordLen),
	}

	return append(recordHeader, fullHandshake...)
}

func TestExecuteStrategyAndRelayDomainMatching(t *testing.T) {
	rules := []config.DomainRuleConfig{
		{Match: "split.example.com", Profile: "write-split-prof"},
		{Match: "*.wildcard.org", Profile: "multi-write-prof"},
		{Match: "bad.target.com", Profile: "non-existent-profile"},
	}
	matcher, err := config.NewDomainMatcher(rules)
	if err != nil {
		t.Fatalf("failed to create DomainMatcher: %v", err)
	}

	profiles := map[string]config.ProfileConfig{
		"none":             {Type: "none"},
		"write-split-prof": {Type: "tcp-write-split", Offset: "sni-mid"},
		"multi-write-prof": {Type: "multi-write-split", ChunkSize: 16, MaxChunks: 8},
	}

	cfg := HandlerConfig{
		DialTimeout:              time.Second,
		IdleTimeout:              time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
		Profiles:                 profiles,
		Matcher:                  matcher,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("SNI matches exact domain rule", func(t *testing.T) {
		clientHello := buildSyntheticClientHello("split.example.com")
		clientR, clientW := net.Pipe()
		defer clientR.Close()
		defer clientW.Close()

		upstreamRecord := &recordingConn{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- ExecuteStrategyAndRelay(ctx, clientR, upstreamRecord, clientHello, "127.0.0.1", logger, cfg)
		}()

		// Allow execution to complete chunks
		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		// Expected write-split-prof: exactly 2 write chunks
		if len(upstreamRecord.writes) != 2 {
			t.Fatalf("expected 2 write chunks for write-split-prof, got %d", len(upstreamRecord.writes))
		}

		// Combined bytes must equal original clientHello
		combined := bytes.Join(upstreamRecord.writes, nil)
		if !bytes.Equal(combined, clientHello) {
			t.Fatal("combined chunks do not match original clientHello")
		}
	})

	t.Run("SNI on IP literal target host matches rule", func(t *testing.T) {
		// When client dialed an IP literal (e.g. SOCKS5 with IPv4 address), SNI still matches!
		clientHello := buildSyntheticClientHello("sub.wildcard.org")
		clientR, clientW := net.Pipe()
		defer clientR.Close()
		defer clientW.Close()

		upstreamRecord := &recordingConn{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- ExecuteStrategyAndRelay(ctx, clientR, upstreamRecord, clientHello, "93.184.216.34", logger, cfg)
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		// Expected multi-write-prof: > 2 chunks
		if len(upstreamRecord.writes) <= 2 {
			t.Fatalf("expected > 2 write chunks for multi-write-prof, got %d", len(upstreamRecord.writes))
		}
		combined := bytes.Join(upstreamRecord.writes, nil)
		if !bytes.Equal(combined, clientHello) {
			t.Fatal("combined chunks do not match original clientHello")
		}
	})

	t.Run("targetHost matches when SNI absent", func(t *testing.T) {
		// Non-TLS initial data (e.g. plain HTTP GET or generic traffic)
		plainData := []byte("GET / HTTP/1.1\r\nHost: split.example.com\r\n\r\n")
		clientR, clientW := net.Pipe()
		defer clientR.Close()
		defer clientW.Close()

		upstreamRecord := &recordingConn{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- ExecuteStrategyAndRelay(ctx, clientR, upstreamRecord, plainData, "split.example.com", logger, cfg)
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		// write-split with sni-mid on non-TLS input falls back to none gracefully (1 chunk)
		combined := bytes.Join(upstreamRecord.writes, nil)
		if !bytes.Equal(combined, plainData) {
			t.Fatal("combined bytes do not match original data")
		}
	})

	t.Run("unmatched domain falls back to default profile", func(t *testing.T) {
		clientHello := buildSyntheticClientHello("unmatched.org")
		clientR, clientW := net.Pipe()
		defer clientR.Close()
		defer clientW.Close()

		upstreamRecord := &recordingConn{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- ExecuteStrategyAndRelay(ctx, clientR, upstreamRecord, clientHello, "unmatched.org", logger, cfg)
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		// Default profile is none: exactly 1 chunk
		if len(upstreamRecord.writes) != 1 {
			t.Fatalf("expected 1 write chunk for none baseline, got %d", len(upstreamRecord.writes))
		}
		if !bytes.Equal(upstreamRecord.writes[0], clientHello) {
			t.Fatal("written bytes do not match original clientHello")
		}
	})

	t.Run("rule referencing unknown profile aborts connection with error", func(t *testing.T) {
		clientHello := buildSyntheticClientHello("bad.target.com")
		clientR, clientW := net.Pipe()
		defer clientR.Close()
		defer clientW.Close()

		upstreamRecord := &recordingConn{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := ExecuteStrategyAndRelay(ctx, clientR, upstreamRecord, clientHello, "bad.target.com", logger, cfg)
		if err == nil {
			t.Fatal("expected error when domain rule references unknown profile, got nil")
		}
		if !strings.Contains(err.Error(), "undefined profile") {
			t.Fatalf("expected 'undefined profile' in error, got: %v", err)
		}

		// Upstream connection must NOT have received any forwarded traffic
		if len(upstreamRecord.writes) != 0 {
			t.Fatalf("expected 0 writes to upstream on abort, got %d", len(upstreamRecord.writes))
		}
	})
}

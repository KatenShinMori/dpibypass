package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"dpibypass/internal/tlsparse"
)

// buildSyntheticClientHelloForTest creates a valid single-record TLS ClientHello.
func buildSyntheticClientHelloForTest(serverName string) []byte {
	nameBytes := []byte(serverName)
	sniPayload := make([]byte, 2+1+2+len(nameBytes))
	sniPayload[0] = byte((len(nameBytes) + 3) >> 8)
	sniPayload[1] = byte(len(nameBytes) + 3)
	sniPayload[2] = 0x00
	sniPayload[3] = byte(len(nameBytes) >> 8)
	sniPayload[4] = byte(len(nameBytes))
	copy(sniPayload[5:], nameBytes)

	dummyExt := []byte{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}
	extVec := make([]byte, 4+len(sniPayload)+len(dummyExt))
	extVec[0] = 0x00
	extVec[1] = 0x00
	extVec[2] = byte(len(sniPayload) >> 8)
	extVec[3] = byte(len(sniPayload))
	copy(extVec[4:], sniPayload)
	copy(extVec[4+len(sniPayload):], dummyExt)

	body := make([]byte, 2+32+1+4+2+2+len(extVec))
	body[0] = 0x03
	body[1] = 0x03
	for i := 2; i < 34; i++ {
		body[i] = 0x01
	}
	body[34] = 0x00
	body[35] = 0x00
	body[36] = 0x02
	body[37] = 0x00
	body[38] = 0x2f
	body[39] = 0x01
	body[40] = 0x00
	body[41] = byte(len(extVec) >> 8)
	body[42] = byte(len(extVec))
	copy(body[43:], extVec)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(handshake) >> 8)
	record[4] = byte(len(handshake))
	copy(record[5:], handshake)

	return record
}

func TestAccumulatorPreBufferedComplete(t *testing.T) {
	raw := buildSyntheticClientHelloForTest("prebuffered.com")
	clientConn, _ := net.Pipe()
	defer clientConn.Close()

	buf, res, err := AccumulateInitialData(context.Background(), clientConn, raw, 100*time.Millisecond, 65536)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != tlsparse.StatusParsed {
		t.Fatalf("expected StatusParsed, got %s", res.Status)
	}
	if !bytes.Equal(buf, raw) {
		t.Fatal("accumulated buffer != raw")
	}
}

func TestAccumulatorIncrementalReads(t *testing.T) {
	raw := buildSyntheticClientHelloForTest("incremental.com")
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	// Feed in 10-byte chunks asynchronously
	go func() {
		offset := 0
		for offset < len(raw) {
			chunkSize := 10
			if offset+chunkSize > len(raw) {
				chunkSize = len(raw) - offset
			}
			_, _ = serverPipe.Write(raw[offset : offset+chunkSize])
			offset += chunkSize
			time.Sleep(5 * time.Millisecond)
		}
	}()

	buf, res, err := AccumulateInitialData(context.Background(), clientPipe, nil, 500*time.Millisecond, 65536)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != tlsparse.StatusParsed {
		t.Fatalf("expected StatusParsed, got %s", res.Status)
	}
	if !bytes.Equal(buf, raw) {
		t.Fatal("accumulated buffer != raw")
	}
}

func TestAccumulatorTimeoutPreservesBytes(t *testing.T) {
	partial := []byte{0x16, 0x03, 0x01, 0x00, 0x20} // Incomplete TLS record header
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	buf, res, err := AccumulateInitialData(context.Background(), clientPipe, partial, 20*time.Millisecond, 65536)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Reason != "inspection_timeout" {
		t.Fatalf("expected inspection_timeout, got reason=%s", res.Reason)
	}
	if !bytes.Equal(buf, partial) {
		t.Fatal("bytes not preserved upon timeout")
	}
}

func TestAccumulatorNonTLSImmediateReturn(t *testing.T) {
	nonTLS := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	clientPipe, _ := net.Pipe()
	defer clientPipe.Close()

	buf, res, err := AccumulateInitialData(context.Background(), clientPipe, nonTLS, 500*time.Millisecond, 65536)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != tlsparse.StatusNotTLS {
		t.Fatalf("expected StatusNotTLS, got %s", res.Status)
	}
	if !bytes.Equal(buf, nonTLS) {
		t.Fatal("bytes not preserved for non-TLS")
	}
}

func TestAccumulatorMaxBytesLimit(t *testing.T) {
	// 5-byte header indicating 1000-byte record payload: 0x16, 0x03, 0x01, 0x03, 0xe8
	partial := []byte{0x16, 0x03, 0x01, 0x03, 0xe8}
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	go func() {
		// Keep sending data chunks until closed
		for {
			_, err := serverPipe.Write([]byte{0x01, 0x02, 0x03, 0x04})
			if err != nil {
				return
			}
		}
	}()

	maxBytes := 200
	buf, res, err := AccumulateInitialData(context.Background(), clientPipe, partial, 500*time.Millisecond, maxBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(buf) != maxBytes {
		t.Fatalf("expected len %d, got %d", maxBytes, len(buf))
	}
	if res.Status != tlsparse.StatusLimitExceeded {
		t.Fatalf("expected StatusLimitExceeded, got %s", res.Status)
	}
}

package strategy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/tlsparse"
)

// recordingMockWriter implements io.Writer and records each discrete Write() call.
// It supports simulating partial writes and injected write errors.
type recordingMockWriter struct {
	writes          [][]byte
	maxWritePerCall int // if > 0, restricts each Write() call to at most this many bytes
	errAfterBytes   int // if > 0, returns an error after writing this many bytes
	totalBytes      int
}

func (m *recordingMockWriter) Write(p []byte) (int, error) {
	if m.errAfterBytes > 0 && m.totalBytes >= m.errAfterBytes {
		return 0, errors.New("simulated socket write error")
	}

	writeLen := len(p)
	if m.maxWritePerCall > 0 && writeLen > m.maxWritePerCall {
		writeLen = m.maxWritePerCall
	}

	if m.errAfterBytes > 0 && m.totalBytes+writeLen > m.errAfterBytes {
		writeLen = m.errAfterBytes - m.totalBytes
		if writeLen <= 0 {
			return 0, errors.New("simulated socket write error")
		}
	}

	chunk := make([]byte, writeLen)
	copy(chunk, p[:writeLen])
	m.writes = append(m.writes, chunk)
	m.totalBytes += writeLen

	return writeLen, nil
}

func (m *recordingMockWriter) ConcatenatedBytes() []byte {
	var buf bytes.Buffer
	for _, w := range m.writes {
		buf.Write(w)
	}
	return buf.Bytes()
}

// buildSyntheticClientHello creates a valid single-record TLS 1.2 ClientHello with SNI.
func buildSyntheticClientHello(serverName string) []byte {
	nameBytes := []byte(serverName)

	// SNI extension payload:
	// list length (2) + name type 0x00 (1) + name length (2) + name bytes
	sniPayload := make([]byte, 2+1+2+len(nameBytes))
	sniPayload[0] = byte((len(nameBytes) + 3) >> 8)
	sniPayload[1] = byte(len(nameBytes) + 3)
	sniPayload[2] = 0x00 // host_name
	sniPayload[3] = byte(len(nameBytes) >> 8)
	sniPayload[4] = byte(len(nameBytes))
	copy(sniPayload[5:], nameBytes)

	// Trailing extension (e.g. supported_groups 0x000a) after SNI:
	dummyExt := []byte{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}
	extVec := make([]byte, 4+len(sniPayload)+len(dummyExt))
	extVec[0] = 0x00
	extVec[1] = 0x00
	extVec[2] = byte(len(sniPayload) >> 8)
	extVec[3] = byte(len(sniPayload))
	copy(extVec[4:], sniPayload)
	copy(extVec[4+len(sniPayload):], dummyExt)

	// Handshake Body:
	// Version 0x0303 (2) + Random (32) + SessionID len 0 (1) + CipherSuites (4) + Compression (2) + ExtsLen (2) + extVec
	body := make([]byte, 2+32+1+4+2+2+len(extVec))
	body[0] = 0x03
	body[1] = 0x03
	// Random 32 bytes (all 0x01)
	for i := 2; i < 34; i++ {
		body[i] = 0x01
	}
	body[34] = 0x00 // session ID length 0
	// Cipher Suites length 2 + 1 suite (0x002f)
	body[35] = 0x00
	body[36] = 0x02
	body[37] = 0x00
	body[38] = 0x2f
	// Compression methods length 1 + 0x00
	body[39] = 0x01
	body[40] = 0x00
	// Extensions vector length
	body[41] = byte(len(extVec) >> 8)
	body[42] = byte(len(extVec))
	copy(body[43:], extVec)

	// Handshake Message: Type 0x01 (1) + uint24 len (3) + body
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	// TLS Record: Type 0x16 (1) + Version 0x0301 (2) + uint16 len (2) + handshake
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(handshake) >> 8)
	record[4] = byte(len(handshake))
	copy(record[5:], handshake)

	return record
}

// buildSyntheticClientHelloWithoutSNI creates a valid single-record TLS 1.2 ClientHello without SNI.
func buildSyntheticClientHelloWithoutSNI() []byte {
	dummyExt := []byte{0x00, 0x0a, 0x00, 0x02, 0x00, 0x1d}
	extVec := make([]byte, len(dummyExt))
	copy(extVec, dummyExt)

	body := make([]byte, 2+32+1+4+2+2+len(extVec))
	body[0] = 0x03
	body[1] = 0x03
	for i := 2; i < 34; i++ {
		body[i] = 0x01
	}
	body[34] = 0x00 // session ID length 0
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

func TestNoneStrategy(t *testing.T) {
	raw := buildSyntheticClientHello("example.com")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("expected parsed status, got %s", parseRes.Status)
	}

	strat := NewNoneStrategy()
	plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil {
		t.Fatalf("unexpected Plan error: %v", err)
	}

	if plan.IsFallback {
		t.Fatal("expected IsFallback=false for NoneStrategy")
	}
	if len(plan.Chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(plan.Chunks))
	}
	if !bytes.Equal(plan.Chunks[0].Data, raw) {
		t.Fatal("chunks[0] does not match original raw bytes")
	}

	rec := &recordingMockWriter{}
	n, err := Execute(context.Background(), rec, plan)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("expected %d bytes written, got %d", len(raw), n)
	}
	if !bytes.Equal(rec.ConcatenatedBytes(), raw) {
		t.Fatal("concatenated bytes mismatch for NoneStrategy")
	}
}

func TestTCPWriteSplitStrategyBytePreservation(t *testing.T) {
	raw := buildSyntheticClientHello("test.example.org")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("expected parsed status, got %s", parseRes.Status)
	}

	offsets := []string{"sni-start", "sni-mid", "sni-end", "5", "20"}

	for _, off := range offsets {
		t.Run("offset_"+off, func(t *testing.T) {
			strat := NewTCPWriteSplitStrategy(off, 0)
			plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
			if err != nil {
				t.Fatalf("plan error: %v", err)
			}
			if plan.IsFallback {
				t.Fatalf("unexpected fallback for offset %q: reason=%s", off, plan.FallbackReason)
			}
			if len(plan.Chunks) != 2 {
				t.Fatalf("expected exactly 2 chunks, got %d", len(plan.Chunks))
			}

			// Invariant: sum of chunks equals len(raw)
			if len(plan.Chunks[0].Data)+len(plan.Chunks[1].Data) != len(raw) {
				t.Fatalf("chunk byte count sum %d != original len %d",
					len(plan.Chunks[0].Data)+len(plan.Chunks[1].Data), len(raw))
			}

			// Invariant: byte concatenation exactly equals raw
			concatenated := append([]byte(nil), plan.Chunks[0].Data...)
			concatenated = append(concatenated, plan.Chunks[1].Data...)
			if !bytes.Equal(concatenated, raw) {
				t.Fatal("concatenated chunks do not equal original raw stream")
			}

			// Execute using recording mock writer
			rec := &recordingMockWriter{}
			n, err := Execute(context.Background(), rec, plan)
			if err != nil {
				t.Fatalf("execute error: %v", err)
			}
			if n != len(raw) {
				t.Fatalf("written byte count %d != raw len %d", n, len(raw))
			}
			if !bytes.Equal(rec.ConcatenatedBytes(), raw) {
				t.Fatal("recorded stream mismatch")
			}
		})
	}
}

func TestTCPWriteSplitPartialWrites(t *testing.T) {
	raw := buildSyntheticClientHello("short.org")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())

	strat := NewTCPWriteSplitStrategy("sni-mid", 0)
	plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil {
		t.Fatalf("plan error: %v", err)
	}

	// Restrict mock writer to at most 3 bytes per call to test socket partial-write loops
	rec := &recordingMockWriter{maxWritePerCall: 3}
	n, err := Execute(context.Background(), rec, plan)
	if err != nil {
		t.Fatalf("execute error during partial writes: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("expected %d bytes, got %d", len(raw), n)
	}
	if !bytes.Equal(rec.ConcatenatedBytes(), raw) {
		t.Fatal("concatenated bytes corrupted during partial write handling")
	}
	if len(rec.writes) < 5 {
		t.Fatalf("expected multiple small writes due to maxWritePerCall=3, got %d writes", len(rec.writes))
	}
}

func TestTCPWriteSplitErrorAbortsConnection(t *testing.T) {
	raw := buildSyntheticClientHello("example.net")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())

	strat := NewTCPWriteSplitStrategy("sni-mid", 0)
	plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil {
		t.Fatalf("plan error: %v", err)
	}

	// Inject error after 10 bytes have been written
	rec := &recordingMockWriter{errAfterBytes: 10}
	n, err := Execute(context.Background(), rec, plan)
	if err == nil {
		t.Fatal("expected error on injected write failure, got nil")
	}
	if !errors.Is(err, ErrAbortedPartialWrite) {
		t.Fatalf("expected ErrAbortedPartialWrite, got %v", err)
	}
	if n != 10 {
		t.Fatalf("expected 10 bytes written before error, got %d", n)
	}
}

func TestTCPWriteSplitPreconditionFallback(t *testing.T) {
	// Raw non-TLS data
	nonTLS := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	strat := NewTCPWriteSplitStrategy("sni-mid", 0)
	plan, err := strat.Plan(context.Background(), nonTLS, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.IsFallback {
		t.Fatal("expected IsFallback=true for non-TLS data")
	}
	if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, nonTLS) {
		t.Fatal("fallback plan did not preserve original bytes unchanged")
	}
}

func TestMultiWriteSplitStrategy(t *testing.T) {
	raw := buildSyntheticClientHello("multi.write.test")

	strat := NewMultiWriteSplitStrategy(10, 8, 0)
	plan, err := strat.Plan(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("multi-write plan error: %v", err)
	}

	if plan.IsFallback {
		t.Fatal("unexpected fallback")
	}
	if len(plan.Chunks) > 8 {
		t.Fatalf("expected at most 8 chunks, got %d", len(plan.Chunks))
	}

	// Assert byte preservation
	var concatenated []byte
	for _, c := range plan.Chunks {
		concatenated = append(concatenated, c.Data...)
	}
	if !bytes.Equal(concatenated, raw) {
		t.Fatal("multi-write chunks do not reconstruct original byte stream")
	}

	rec := &recordingMockWriter{}
	n, err := Execute(context.Background(), rec, plan)
	if err != nil {
		t.Fatalf("execute error: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("expected %d bytes, got %d", len(raw), n)
	}
	if !bytes.Equal(rec.ConcatenatedBytes(), raw) {
		t.Fatal("recorded stream mismatch in multi-write")
	}
}

func TestTLSRecordSplitStrategy(t *testing.T) {
	raw := buildSyntheticClientHello("record.split.domain")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("parse failed: %s", parseRes.Status)
	}

	strat := NewTLSRecordSplitStrategy("sni-mid")
	plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil {
		t.Fatalf("record-split plan error: %v", err)
	}
	if plan.IsFallback {
		t.Fatalf("unexpected record-split fallback: %s", plan.FallbackReason)
	}
	if len(plan.Chunks) != 1 {
		t.Fatalf("expected 1 chunk containing synthesized records, got %d", len(plan.Chunks))
	}

	synthesized := plan.Chunks[0].Data

	// Verify the synthesized output:
	// 1. Must parse cleanly with tlsparse
	reparse := tlsparse.ParseClientHello(synthesized, tlsparse.DefaultLimits())
	if reparse.Status != tlsparse.StatusParsed {
		t.Fatalf("synthesized records failed re-parse: %s", reparse.Status)
	}
	// 2. Must be fragmented across exactly 2 records
	if !reparse.Metadata.IsFragmented || len(reparse.Metadata.Records) != 2 {
		t.Fatalf("expected 2 fragmented records, got fragmented=%v, count=%d",
			reparse.Metadata.IsFragmented, len(reparse.Metadata.Records))
	}
	// 3. SNI must match original exactly
	if reparse.Metadata.SNI != "record.split.domain" {
		t.Fatalf("expected SNI 'record.split.domain', got %q", reparse.Metadata.SNI)
	}
	// 4. Logical handshake length must match original logical handshake length
	if reparse.Metadata.LogicalHandshakeLength != parseRes.Metadata.LogicalHandshakeLength {
		t.Fatalf("handshake length mismatch: got %d, expected %d",
			reparse.Metadata.LogicalHandshakeLength, parseRes.Metadata.LogicalHandshakeLength)
	}
}

func TestTLSRecordSplitTrailingPayloadSafety(t *testing.T) {
	strat := NewTLSRecordSplitStrategy("sni-mid")

	t.Run("standard ClientHello transforms successfully into 2 records", func(t *testing.T) {
		raw := buildSyntheticClientHello("standard.example.com")
		parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
		if parseRes.Status != tlsparse.StatusParsed {
			t.Fatalf("parse failed: %s", parseRes.Status)
		}

		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if plan.IsFallback {
			t.Fatalf("expected IsFallback=false, got reason: %s", plan.FallbackReason)
		}
		if len(plan.Chunks) != 1 {
			t.Fatalf("expected 1 chunk, got %d", len(plan.Chunks))
		}

		reparse := tlsparse.ParseClientHello(plan.Chunks[0].Data, tlsparse.DefaultLimits())
		if reparse.Status != tlsparse.StatusParsed || len(reparse.Metadata.Records) != 2 {
			t.Fatalf("expected 2 parsed records, got %v", reparse.Metadata)
		}
		if reparse.Metadata.HasTrailingData {
			t.Fatal("expected no trailing data in synthesized output")
		}
		if reparse.Metadata.ConsumedWireBytes != len(plan.Chunks[0].Data) {
			t.Fatalf("consumed wire bytes %d != buffer len %d", reparse.Metadata.ConsumedWireBytes, len(plan.Chunks[0].Data))
		}
	})

	t.Run("intra-record trailing payload falls back with byte preservation", func(t *testing.T) {
		// Single TLS record whose payload extends beyond the complete ClientHello
		raw := buildSyntheticClientHello("intra-trailing.example.com")
		trailingPayload := []byte{0x0b, 0x00, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}

		intraWire := make([]byte, len(raw)+len(trailingPayload))
		copy(intraWire, raw)
		copy(intraWire[len(raw):], trailingPayload)
		// Update record header payload length field at bytes [3:5]
		origPayloadLen := int(binary.BigEndian.Uint16(raw[3:5]))
		binary.BigEndian.PutUint16(intraWire[3:5], uint16(origPayloadLen+len(trailingPayload)))

		parseRes := tlsparse.ParseClientHello(intraWire, tlsparse.DefaultLimits())
		if parseRes.Status != tlsparse.StatusParsed {
			t.Fatalf("expected StatusParsed, got %s: %s", parseRes.Status, parseRes.Reason)
		}
		if !parseRes.Metadata.HasTrailingData {
			t.Fatal("expected HasTrailingData=true on test fixture")
		}
		if parseRes.Metadata.Records[0].PayloadRemaining != len(trailingPayload) {
			t.Fatalf("expected PayloadRemaining=%d, got %d", len(trailingPayload), parseRes.Metadata.Records[0].PayloadRemaining)
		}

		plan, err := strat.Plan(context.Background(), intraWire, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected IsFallback=true for intra-record trailing payload")
		}
		if !strings.Contains(plan.FallbackReason, "trailing") {
			t.Fatalf("expected meaningful trailing fallback reason, got: %q", plan.FallbackReason)
		}
		if len(plan.Chunks) != 1 {
			t.Fatalf("expected exactly 1 chunk on fallback, got %d", len(plan.Chunks))
		}
		if !bytes.Equal(plan.Chunks[0].Data, intraWire) {
			t.Fatal("fallback chunk data is not byte-for-byte identical to input")
		}

		// Execute through mock writer to ensure end-to-end stream preservation
		rec := &recordingMockWriter{}
		n, err := Execute(context.Background(), rec, plan)
		if err != nil {
			t.Fatalf("Execute error: %v", err)
		}
		if n != len(intraWire) {
			t.Fatalf("expected %d bytes written, got %d", len(intraWire), n)
		}
		if !bytes.Equal(rec.ConcatenatedBytes(), intraWire) {
			t.Fatal("executed stream mismatch: fallback did not preserve exact bytes")
		}
	})

	t.Run("post-record trailing wire bytes falls back with byte preservation", func(t *testing.T) {
		// Complete valid TLS record followed by extra wire bytes in the buffer
		raw := buildSyntheticClientHello("post-trailing.example.com")
		postWire := append(raw, []byte("EXTRA_TRAILING_BYTES_ON_WIRE")...)

		parseRes := tlsparse.ParseClientHello(postWire, tlsparse.DefaultLimits())
		if parseRes.Status != tlsparse.StatusParsed {
			t.Fatalf("expected StatusParsed, got %s: %s", parseRes.Status, parseRes.Reason)
		}
		if !parseRes.Metadata.HasTrailingData {
			t.Fatal("expected HasTrailingData=true on post-record test fixture")
		}

		plan, err := strat.Plan(context.Background(), postWire, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected IsFallback=true for post-record trailing wire bytes")
		}
		if !strings.Contains(plan.FallbackReason, "trailing") {
			t.Fatalf("expected meaningful trailing fallback reason, got: %q", plan.FallbackReason)
		}
		if len(plan.Chunks) != 1 {
			t.Fatalf("expected 1 chunk on fallback, got %d", len(plan.Chunks))
		}
		if !bytes.Equal(plan.Chunks[0].Data, postWire) {
			t.Fatal("fallback chunk data is not byte-for-byte identical to input")
		}

		// Execute through mock writer to ensure end-to-end stream preservation
		rec := &recordingMockWriter{}
		n, err := Execute(context.Background(), rec, plan)
		if err != nil {
			t.Fatalf("Execute error: %v", err)
		}
		if n != len(postWire) {
			t.Fatalf("expected %d bytes written, got %d", len(postWire), n)
		}
		if !bytes.Equal(rec.ConcatenatedBytes(), postWire) {
			t.Fatal("executed stream mismatch: fallback did not preserve exact bytes")
		}
	})

	t.Run("combined intra-record and post-record trailing bytes falls back with byte preservation", func(t *testing.T) {
		raw := buildSyntheticClientHello("combined-trailing.example.com")
		trailingPayload := []byte{0x0b, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33}
		postWireBytes := []byte("POST_RECORD_EXTRA_DATA")

		combinedWire := make([]byte, len(raw)+len(trailingPayload)+len(postWireBytes))
		copy(combinedWire, raw)
		copy(combinedWire[len(raw):], trailingPayload)
		copy(combinedWire[len(raw)+len(trailingPayload):], postWireBytes)

		origPayloadLen := int(binary.BigEndian.Uint16(raw[3:5]))
		binary.BigEndian.PutUint16(combinedWire[3:5], uint16(origPayloadLen+len(trailingPayload)))

		parseRes := tlsparse.ParseClientHello(combinedWire, tlsparse.DefaultLimits())
		if parseRes.Status != tlsparse.StatusParsed {
			t.Fatalf("expected StatusParsed, got %s: %s", parseRes.Status, parseRes.Reason)
		}
		if !parseRes.Metadata.HasTrailingData {
			t.Fatal("expected HasTrailingData=true on combined fixture")
		}

		plan, err := strat.Plan(context.Background(), combinedWire, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected IsFallback=true for combined trailing payload")
		}
		if !strings.Contains(plan.FallbackReason, "trailing") {
			t.Fatalf("expected meaningful trailing fallback reason, got: %q", plan.FallbackReason)
		}
		if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, combinedWire) {
			t.Fatal("fallback chunk data is not byte-for-byte identical to input")
		}

		rec := &recordingMockWriter{}
		n, err := Execute(context.Background(), rec, plan)
		if err != nil || n != len(combinedWire) || !bytes.Equal(rec.ConcatenatedBytes(), combinedWire) {
			t.Fatal("stream execution failed to preserve exact bytes")
		}
	})

	t.Run("composite strategy safely falls back on trailing data", func(t *testing.T) {
		raw := buildSyntheticClientHello("composite-trailing.example.com")
		trailingPayload := []byte{0x0b, 0x00, 0x00, 0x02, 0x01, 0x02}
		intraWire := make([]byte, len(raw)+len(trailingPayload))
		copy(intraWire, raw)
		copy(intraWire[len(raw):], trailingPayload)
		origPayloadLen := int(binary.BigEndian.Uint16(raw[3:5]))
		binary.BigEndian.PutUint16(intraWire[3:5], uint16(origPayloadLen+len(trailingPayload)))

		parseRes := tlsparse.ParseClientHello(intraWire, tlsparse.DefaultLimits())
		compositeStrat := NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0)
		plan, err := compositeStrat.Plan(context.Background(), intraWire, parseRes.Metadata)
		if err != nil {
			t.Fatalf("composite plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected composite plan to fall back on trailing data")
		}
		if !strings.Contains(plan.FallbackReason, "trailing") {
			t.Fatalf("expected trailing fallback reason in composite plan, got: %q", plan.FallbackReason)
		}
		if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, intraWire) {
			t.Fatal("composite fallback data mismatch")
		}
	})

	t.Run("malformed and unsupported inputs fail safely without panic", func(t *testing.T) {
		// 1. nil metadata
		raw := buildSyntheticClientHello("nilmeta.example.com")
		plan, err := strat.Plan(context.Background(), raw, nil)
		if err != nil || !plan.IsFallback || plan.FallbackReason != "no_client_hello_metadata" {
			t.Fatalf("unexpected nil meta behavior: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("nil meta fallback did not preserve input bytes")
		}

		// 2. empty input
		plan, err = strat.Plan(context.Background(), nil, nil)
		if err != nil || len(plan.Chunks) != 0 {
			t.Fatalf("unexpected empty input behavior: %v, %v", err, plan)
		}

		// 3. fragmented input (multi-record ClientHello)
		fakeMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented: true,
			Records:      make([]tlsparse.RecordBoundary, 2),
		}
		plan, err = strat.Plan(context.Background(), raw, fakeMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != ErrNotSingleRecord.Error() {
			t.Fatalf("unexpected fragmented fallback: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("fragmented fallback did not preserve input bytes")
		}

		// 4. handshake length too small
		shortMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented:           false,
			Records:                []tlsparse.RecordBoundary{{HeaderLen: 5, WireOffset: 0}},
			LogicalHandshakeLength: 3,
		}
		plan, err = strat.Plan(context.Background(), raw, shortMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != "handshake_length_too_small" {
			t.Fatalf("unexpected short handshake fallback: %v, %v", err, plan)
		}

		// 5. truncated input buffer (handshake start + len > len(input))
		truncRaw := raw[:10]
		truncMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented:           false,
			Records:                []tlsparse.RecordBoundary{{HeaderLen: 5, WireOffset: 0}},
			LogicalHandshakeLength: 20,
		}
		plan, err = strat.Plan(context.Background(), truncRaw, truncMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != "handshake_bytes_truncated_in_buffer" {
			t.Fatalf("unexpected truncated buffer fallback: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, truncRaw) {
			t.Fatal("truncated buffer fallback did not preserve input bytes")
		}

		// 6. non-zero wire offset (leading data before record)
		leadingRaw := append([]byte("LEADING_DATA"), raw...)
		leadingMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented:           false,
			Records:                []tlsparse.RecordBoundary{{HeaderLen: 5, WireOffset: 12, PayloadConsumed: len(raw) - 5}},
			LogicalHandshakeLength: len(raw) - 5,
			ConsumedWireBytes:      len(leadingRaw),
		}
		plan, err = strat.Plan(context.Background(), leadingRaw, leadingMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != ErrNotSingleRecord.Error() {
			t.Fatalf("unexpected non-zero WireOffset fallback: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, leadingRaw) {
			t.Fatal("non-zero WireOffset fallback did not preserve input bytes")
		}

		// 7. non-standard header length
		badHdrMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented:           false,
			Records:                []tlsparse.RecordBoundary{{HeaderLen: 4, WireOffset: 0, PayloadConsumed: len(raw) - 5}},
			LogicalHandshakeLength: len(raw) - 5,
			ConsumedWireBytes:      len(raw),
		}
		plan, err = strat.Plan(context.Background(), raw, badHdrMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != ErrNotSingleRecord.Error() {
			t.Fatalf("unexpected bad header length fallback: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("bad header length fallback did not preserve input bytes")
		}

		// 8. unconsumed record payload mismatch
		unconsumedMeta := &tlsparse.ClientHelloMetadata{
			IsFragmented:           false,
			Records:                []tlsparse.RecordBoundary{{HeaderLen: 5, WireOffset: 0, PayloadConsumed: len(raw) - 10, PayloadRemaining: 0}},
			LogicalHandshakeLength: len(raw) - 5,
			ConsumedWireBytes:      len(raw),
		}
		plan, err = strat.Plan(context.Background(), raw, unconsumedMeta)
		if err != nil || !plan.IsFallback || plan.FallbackReason != ErrTrailingDataUnsupported.Error() {
			t.Fatalf("unexpected unconsumed payload fallback: %v, %v", err, plan)
		}
		if !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("unconsumed payload fallback did not preserve input bytes")
		}
	})
}

func TestCompositeRecordThenWriteSplit(t *testing.T) {
	raw := buildSyntheticClientHello("composite.example.com")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())

	strat := NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0)
	plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil {
		t.Fatalf("composite plan error: %v", err)
	}
	if plan.IsFallback {
		t.Fatalf("composite plan fell back: %s", plan.FallbackReason)
	}
	if len(plan.Chunks) != 2 {
		t.Fatalf("expected 2 chunks from composite strategy, got %d", len(plan.Chunks))
	}

	// Verify concatenation reassembles valid fragmented ClientHello
	concatenated := append([]byte(nil), plan.Chunks[0].Data...)
	concatenated = append(concatenated, plan.Chunks[1].Data...)

	reparse := tlsparse.ParseClientHello(concatenated, tlsparse.DefaultLimits())
	if reparse.Status != tlsparse.StatusParsed {
		t.Fatalf("composite output failed re-parse: %s", reparse.Status)
	}
	if !reparse.Metadata.IsFragmented {
		t.Fatal("expected fragmented metadata in composite output")
	}
	if reparse.Metadata.SNI != "composite.example.com" {
		t.Fatalf("SNI mismatch: %q", reparse.Metadata.SNI)
	}
}

func TestHTTPHostTweakStrategy(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"

	t.Run("lowercase", func(t *testing.T) {
		strat := NewHTTPHostTweakStrategy("lowercase", 0)
		res, chunks := strat.TransformHeaders(req)
		if len(chunks) != 0 {
			t.Fatalf("expected 0 write chunks for lowercase, got %d", len(chunks))
		}
		if !strings.Contains(res, "host: example.com\r\n") {
			t.Fatalf("expected lowercase 'host:', got:\n%s", res)
		}
		if !strings.Contains(res, "Accept: */*") {
			t.Fatal("other headers were not preserved")
		}
	})

	t.Run("space", func(t *testing.T) {
		strat := NewHTTPHostTweakStrategy("space", 0)
		res, _ := strat.TransformHeaders(req)
		if !strings.Contains(res, "Host:  example.com\r\n") {
			t.Fatalf("expected extra space in Host header, got:\n%s", res)
		}
	})

	t.Run("split", func(t *testing.T) {
		strat := NewHTTPHostTweakStrategy("split", 0)
		_, chunks := strat.TransformHeaders(req)
		if len(chunks) != 2 {
			t.Fatalf("expected 2 write chunks for split, got %d", len(chunks))
		}
		concatenated := string(append(chunks[0].Data, chunks[1].Data...))
		if !strings.Contains(concatenated, "Host: example.com") {
			t.Fatalf("concatenated chunks corrupted Host header: %q", concatenated)
		}
	})
}

func TestRegistryFromProfileCompositeOffsets(t *testing.T) {
	t.Run("legacy offset configuration", func(t *testing.T) {
		p := config.ProfileConfig{
			Type:    "tls-record-then-write-split",
			Offset:  "sni-start",
			DelayMS: 25,
		}
		strat, err := FromProfile(p)
		if err != nil {
			t.Fatalf("unexpected FromProfile error: %v", err)
		}
		comp, ok := strat.(*CompositeRecordThenWriteSplitStrategy)
		if !ok {
			t.Fatalf("expected *CompositeRecordThenWriteSplitStrategy, got %T", strat)
		}
		if comp.RecordSplitOffset != "sni-start" {
			t.Errorf("expected RecordSplitOffset 'sni-start', got %q", comp.RecordSplitOffset)
		}
		if comp.WriteSplitOffset != "sni-start" {
			t.Errorf("expected WriteSplitOffset 'sni-start', got %q", comp.WriteSplitOffset)
		}
		if comp.Delay != 25*time.Millisecond {
			t.Errorf("expected Delay 25ms, got %v", comp.Delay)
		}

		// Verify that legacy configuration behaves correctly during Plan execution
		raw := buildSyntheticClientHello("legacy.example.com")
		parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
		if parseRes.Status != tlsparse.StatusParsed {
			t.Fatalf("parse failed: %s", parseRes.Status)
		}
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if plan.IsFallback {
			t.Fatalf("unexpected fallback: %s", plan.FallbackReason)
		}
		if len(plan.Chunks) != 2 {
			t.Fatalf("expected 2 chunks, got %d", len(plan.Chunks))
		}
		if plan.Chunks[1].Delay != 25*time.Millisecond {
			t.Errorf("expected chunk 1 delay 25ms, got %v", plan.Chunks[1].Delay)
		}

		concatenated := append([]byte(nil), plan.Chunks[0].Data...)
		concatenated = append(concatenated, plan.Chunks[1].Data...)
		reparse := tlsparse.ParseClientHello(concatenated, tlsparse.DefaultLimits())
		if reparse.Status != tlsparse.StatusParsed || !reparse.Metadata.IsFragmented {
			t.Fatalf("reparse failed or not fragmented: status=%s", reparse.Status)
		}
	})

	t.Run("independent record_offset and write_offset", func(t *testing.T) {
		p := config.ProfileConfig{
			Type:         "tls-record-then-write-split",
			RecordOffset: "sni-start",
			WriteOffset:  "sni-end",
			DelayMS:      10,
		}
		strat, err := FromProfile(p)
		if err != nil {
			t.Fatalf("unexpected FromProfile error: %v", err)
		}
		comp, ok := strat.(*CompositeRecordThenWriteSplitStrategy)
		if !ok {
			t.Fatalf("expected *CompositeRecordThenWriteSplitStrategy, got %T", strat)
		}
		if comp.RecordSplitOffset != "sni-start" {
			t.Errorf("expected RecordSplitOffset 'sni-start', got %q", comp.RecordSplitOffset)
		}
		if comp.WriteSplitOffset != "sni-end" {
			t.Errorf("expected WriteSplitOffset 'sni-end', got %q", comp.WriteSplitOffset)
		}
	})

	t.Run("precedence of specific over legacy offset", func(t *testing.T) {
		p := config.ProfileConfig{
			Type:         "tls-record-then-write-split",
			Offset:       "sni-mid",
			RecordOffset: "sni-start",
			WriteOffset:  "sni-end",
		}
		strat, err := FromProfile(p)
		if err != nil {
			t.Fatalf("unexpected FromProfile error: %v", err)
		}
		comp := strat.(*CompositeRecordThenWriteSplitStrategy)
		if comp.RecordSplitOffset != "sni-start" {
			t.Errorf("expected RecordSplitOffset 'sni-start', got %q", comp.RecordSplitOffset)
		}
		if comp.WriteSplitOffset != "sni-end" {
			t.Errorf("expected WriteSplitOffset 'sni-end', got %q", comp.WriteSplitOffset)
		}
	})

	t.Run("partial fallback to legacy offset", func(t *testing.T) {
		p := config.ProfileConfig{
			Type:         "tls-record-then-write-split",
			Offset:       "sni-end",
			RecordOffset: "sni-start",
		}
		strat, err := FromProfile(p)
		if err != nil {
			t.Fatalf("unexpected FromProfile error: %v", err)
		}
		comp := strat.(*CompositeRecordThenWriteSplitStrategy)
		if comp.RecordSplitOffset != "sni-start" {
			t.Errorf("expected RecordSplitOffset 'sni-start', got %q", comp.RecordSplitOffset)
		}
		if comp.WriteSplitOffset != "sni-end" {
			t.Errorf("expected WriteSplitOffset 'sni-end', got %q", comp.WriteSplitOffset)
		}
	})

	t.Run("defaults when all offsets omitted", func(t *testing.T) {
		p := config.ProfileConfig{
			Type: "tls-record-then-write-split",
		}
		strat, err := FromProfile(p)
		if err != nil {
			t.Fatalf("unexpected FromProfile error: %v", err)
		}
		comp := strat.(*CompositeRecordThenWriteSplitStrategy)
		if comp.RecordSplitOffset != "sni-mid" {
			t.Errorf("expected default RecordSplitOffset 'sni-mid', got %q", comp.RecordSplitOffset)
		}
		if comp.WriteSplitOffset != "sni-mid" {
			t.Errorf("expected default WriteSplitOffset 'sni-mid', got %q", comp.WriteSplitOffset)
		}
	})
}

func TestCompositeIndependentOffsets(t *testing.T) {
	raw := buildSyntheticClientHello("composite.example.com")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("parse failed: %s", parseRes.Status)
	}

	t.Run("record=sni-start, write=sni-end", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("sni-start", "sni-end", 50*time.Millisecond)
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if plan.IsFallback {
			t.Fatalf("unexpected fallback: %s", plan.FallbackReason)
		}
		if len(plan.Chunks) != 2 {
			t.Fatalf("expected 2 chunks, got %d", len(plan.Chunks))
		}
		if plan.Chunks[1].Delay != 50*time.Millisecond {
			t.Errorf("expected chunk 1 delay 50ms, got %v", plan.Chunks[1].Delay)
		}

		// Concatenation must reconstruct valid fragmented ClientHello
		concatenated := append([]byte(nil), plan.Chunks[0].Data...)
		concatenated = append(concatenated, plan.Chunks[1].Data...)

		reparse := tlsparse.ParseClientHello(concatenated, tlsparse.DefaultLimits())
		if reparse.Status != tlsparse.StatusParsed {
			t.Fatalf("reparse failed: %s", reparse.Status)
		}
		if !reparse.Metadata.IsFragmented || len(reparse.Metadata.Records) != 2 {
			t.Fatalf("expected 2 fragmented records, got fragmented=%v, count=%d",
				reparse.Metadata.IsFragmented, len(reparse.Metadata.Records))
		}
		if reparse.Metadata.SNI != "composite.example.com" {
			t.Errorf("SNI mismatch: %q", reparse.Metadata.SNI)
		}

		// Stage 1 split at sni-start puts SNI in record 2.
		// Stage 2 split at sni-end splits inside record 2 after the SNI.
		// Therefore Chunk 0 contains Record 1 AND the beginning of Record 2.
		rec1WireLen := reparse.Metadata.Records[0].WireOffset + reparse.Metadata.Records[0].HeaderLen + reparse.Metadata.Records[0].PayloadConsumed
		if len(plan.Chunks[0].Data) <= rec1WireLen {
			t.Errorf("expected chunk 0 length (%d) to exceed record 1 length (%d) since write split is at sni-end",
				len(plan.Chunks[0].Data), rec1WireLen)
		}
	})

	t.Run("record=sni-end, write=sni-start", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("sni-end", "sni-start", 0)
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if plan.IsFallback {
			t.Fatalf("unexpected fallback: %s", plan.FallbackReason)
		}
		if len(plan.Chunks) != 2 {
			t.Fatalf("expected 2 chunks, got %d", len(plan.Chunks))
		}

		concatenated := append([]byte(nil), plan.Chunks[0].Data...)
		concatenated = append(concatenated, plan.Chunks[1].Data...)

		reparse := tlsparse.ParseClientHello(concatenated, tlsparse.DefaultLimits())
		if reparse.Status != tlsparse.StatusParsed {
			t.Fatalf("reparse failed: %s", reparse.Status)
		}

		// Stage 1 split at sni-end puts SNI in record 1.
		// Stage 2 split at sni-start splits inside record 1 before the SNI.
		// Therefore Chunk 0 contains Record 1 up to sni-start.
		rec1WireLen := reparse.Metadata.Records[0].WireOffset + reparse.Metadata.Records[0].HeaderLen + reparse.Metadata.Records[0].PayloadConsumed
		if len(plan.Chunks[0].Data) >= rec1WireLen {
			t.Errorf("expected chunk 0 length (%d) to be less than record 1 length (%d) since write split is at sni-start",
				len(plan.Chunks[0].Data), rec1WireLen)
		}
	})

	t.Run("independent numeric offsets", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("20", "40", 0)
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("plan error: %v", err)
		}
		if plan.IsFallback {
			t.Fatalf("unexpected fallback: %s", plan.FallbackReason)
		}
		if len(plan.Chunks) != 2 {
			t.Fatalf("expected 2 chunks, got %d", len(plan.Chunks))
		}
		if len(plan.Chunks[0].Data) != 40 {
			t.Errorf("expected chunk 0 length 40, got %d", len(plan.Chunks[0].Data))
		}

		concatenated := append([]byte(nil), plan.Chunks[0].Data...)
		concatenated = append(concatenated, plan.Chunks[1].Data...)
		reparse := tlsparse.ParseClientHello(concatenated, tlsparse.DefaultLimits())
		if reparse.Status != tlsparse.StatusParsed {
			t.Fatalf("reparse failed: %s", reparse.Status)
		}
	})

	t.Run("fallback when write offset is out of bounds", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("sni-mid", "99999", 0)
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("unexpected plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected fallback when write offset is out of bounds")
		}
		if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("expected fallback to emit exactly 1 chunk with unmodified raw input")
		}
		if plan.FallbackReason == "" {
			t.Error("expected non-empty FallbackReason")
		}
	})

	t.Run("fallback when record offset is out of bounds", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("99999", "sni-mid", 0)
		plan, err := strat.Plan(context.Background(), raw, parseRes.Metadata)
		if err != nil {
			t.Fatalf("unexpected plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected fallback when record offset is out of bounds")
		}
		if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, raw) {
			t.Fatal("expected fallback to emit exactly 1 chunk with unmodified raw input")
		}
		if plan.FallbackReason == "" {
			t.Error("expected non-empty FallbackReason")
		}
	})

	t.Run("fallback when write offset requires SNI but SNI is absent", func(t *testing.T) {
		noSNIRaw := buildSyntheticClientHelloWithoutSNI()
		noSNIParse := tlsparse.ParseClientHello(noSNIRaw, tlsparse.DefaultLimits())
		if noSNIParse.Status != tlsparse.StatusParsed {
			t.Fatalf("no-SNI parse failed: %s", noSNIParse.Status)
		}
		strat := NewCompositeRecordThenWriteSplitStrategy("20", "sni-start", 0)
		plan, err := strat.Plan(context.Background(), noSNIRaw, noSNIParse.Metadata)
		if err != nil {
			t.Fatalf("unexpected plan error: %v", err)
		}
		if !plan.IsFallback {
			t.Fatal("expected fallback when write offset requires SNI on non-SNI input")
		}
		if len(plan.Chunks) != 1 || !bytes.Equal(plan.Chunks[0].Data, noSNIRaw) {
			t.Fatal("expected fallback to emit unmodified raw non-SNI input")
		}
		if !strings.Contains(plan.FallbackReason, "sni hostname is not present") {
			t.Errorf("expected SNI not present fallback reason, got: %q", plan.FallbackReason)
		}
	})
}

func TestLogicalToWireOffsetMultiRecordMapping(t *testing.T) {
	raw := buildSyntheticClientHello("mapping.example.com")
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("parse failed: %s", parseRes.Status)
	}

	// Synthesize a 2-record ClientHello split at sni-mid
	recStrat := NewTLSRecordSplitStrategy("sni-mid")
	recPlan, err := recStrat.Plan(context.Background(), raw, parseRes.Metadata)
	if err != nil || recPlan.IsFallback {
		t.Fatalf("record split failed: %v", err)
	}
	multiRecordWire := recPlan.Chunks[0].Data

	reparse := tlsparse.ParseClientHello(multiRecordWire, tlsparse.DefaultLimits())
	if reparse.Status != tlsparse.StatusParsed || len(reparse.Metadata.Records) != 2 {
		t.Fatalf("expected 2 parsed records, got %d", len(reparse.Metadata.Records))
	}

	meta := reparse.Metadata
	rec1 := meta.Records[0]
	rec2 := meta.Records[1]

	// 1. Logical offset within record 1 payload (e.g. logical offset 10)
	wireOff1, err := LogicalToWireOffset(multiRecordWire, meta, 10, PlacementBeforeRecordHeader)
	if err != nil {
		t.Fatalf("LogicalToWireOffset error for offset 10: %v", err)
	}
	expectedWireOff1 := rec1.WireOffset + rec1.HeaderLen + 10
	if wireOff1 != expectedWireOff1 {
		t.Errorf("expected wire offset %d in record 1, got %d", expectedWireOff1, wireOff1)
	}

	// 2. Logical offset at exact boundary between record 1 and record 2
	boundaryLogical := rec1.PayloadConsumed
	wireOffBoundary, err := LogicalToWireOffset(multiRecordWire, meta, boundaryLogical, PlacementBeforeRecordHeader)
	if err != nil {
		t.Fatalf("LogicalToWireOffset error at boundary: %v", err)
	}
	if wireOffBoundary != rec2.WireOffset {
		t.Errorf("expected boundary wire offset %d (start of record 2), got %d", rec2.WireOffset, wireOffBoundary)
	}

	// 3. Logical offset within record 2 payload (e.g. boundary + 10)
	wireOff2, err := LogicalToWireOffset(multiRecordWire, meta, boundaryLogical+10, PlacementBeforeRecordHeader)
	if err != nil {
		t.Fatalf("LogicalToWireOffset error for offset in record 2: %v", err)
	}
	expectedWireOff2 := rec2.WireOffset + rec2.HeaderLen + 10
	if wireOff2 != expectedWireOff2 {
		t.Errorf("expected wire offset %d in record 2, got %d", expectedWireOff2, wireOff2)
	}

	// 4. Out of bounds logical offset
	_, err = LogicalToWireOffset(multiRecordWire, meta, meta.LogicalHandshakeLength+50, PlacementBeforeRecordHeader)
	if err == nil {
		t.Fatal("expected error for out of bounds logical offset, got nil")
	}
	if !errors.Is(err, ErrOffsetOutOfBounds) {
		t.Errorf("expected ErrOffsetOutOfBounds, got %v", err)
	}
}

func TestExecuteInterWriteDelay(t *testing.T) {
	chunk0 := []byte("chunk-zero-data")
	chunk1 := []byte("chunk-one-data")

	t.Run("non-zero delay is honoured and cancellable", func(t *testing.T) {
		plan := ExecutionPlan{
			StrategyName: "test-delay",
			Chunks: []WriteChunk{
				{Data: chunk0, Delay: 0},
				{Data: chunk1, Delay: 2 * time.Second}, // Intentional long delay
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		chunk0Written := make(chan struct{})
		rec := &delayObservingWriter{
			onWrite: func(data []byte) {
				if bytes.Equal(data, chunk0) {
					close(chunk0Written)
				}
			},
		}

		errCh := make(chan error, 1)
		go func() {
			_, err := Execute(ctx, rec, plan)
			errCh <- err
		}()

		// Wait until chunk 0 has been written
		select {
		case <-chunk0Written:
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for chunk 0 write")
		}

		// Cancel context while Execute is sleeping in inter-write delay
		cancel()

		// Execute must abort with ErrAbortedPartialWrite
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("expected error on context cancellation during delay, got nil")
			}
			if !errors.Is(err, ErrAbortedPartialWrite) {
				t.Fatalf("expected ErrAbortedPartialWrite, got: %v", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("Execute did not return promptly after context cancellation")
		}

		// Assert chunk 1 was never written
		if len(rec.writes) != 1 {
			t.Fatalf("expected exactly 1 write recorded, got %d", len(rec.writes))
		}
		if !bytes.Equal(rec.writes[0], chunk0) {
			t.Fatal("recorded data mismatch for chunk 0")
		}
	})

	t.Run("zero delay executes immediately without blocking", func(t *testing.T) {
		plan := ExecutionPlan{
			StrategyName: "test-zero-delay",
			Chunks: []WriteChunk{
				{Data: chunk0, Delay: 0},
				{Data: chunk1, Delay: 0},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		rec := &recordingMockWriter{}
		n, err := Execute(ctx, rec, plan)
		if err != nil {
			t.Fatalf("unexpected Execute error with zero delay: %v", err)
		}
		if n != len(chunk0)+len(chunk1) {
			t.Errorf("expected %d bytes, got %d", len(chunk0)+len(chunk1), n)
		}
		if len(rec.writes) != 2 {
			t.Fatalf("expected 2 writes, got %d", len(rec.writes))
		}
	})

	t.Run("non-zero delay completes successfully when uncancelled", func(t *testing.T) {
		delay := 20 * time.Millisecond
		plan := ExecutionPlan{
			StrategyName: "test-delay-success",
			Chunks: []WriteChunk{
				{Data: chunk0, Delay: 0},
				{Data: chunk1, Delay: delay},
			},
		}

		rec := &recordingMockWriter{}
		start := time.Now()
		n, err := Execute(context.Background(), rec, plan)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected Execute error: %v", err)
		}
		if n != len(chunk0)+len(chunk1) {
			t.Errorf("expected %d bytes, got %d", len(chunk0)+len(chunk1), n)
		}
		if elapsed < 15*time.Millisecond {
			t.Errorf("expected elapsed time to reflect delay >= 15ms, got %v", elapsed)
		}
	})
}

// delayObservingWriter records writes and triggers a callback per write
type delayObservingWriter struct {
	writes  [][]byte
	onWrite func([]byte)
}

func (w *delayObservingWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	w.writes = append(w.writes, cp)
	if w.onWrite != nil {
		w.onWrite(cp)
	}
	return len(p), nil
}

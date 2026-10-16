package strategy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"dpibypass/internal/tlsparse"
)

// Simulated DPI Inspection Models
//
// CRITICAL DISCLAIMER:
// A pass against NaiveWriteInspector or RecordLayerInspector proves ONLY that a naive or record-isolated
// middlebox model fails to find the SNI string. It does NOT prove that real ISP DPI (which reassembles
// TCP streams and reassembles fragmented TLS records) will be bypassed.
// StreamReassemblingInspector demonstrates that stream-level inspection successfully reconstructs the SNI
// regardless of socket-write splitting or TLS record splitting.

// NaiveWriteInspector inspects each individual conn.Write chunk independently without state or reassembly.
type NaiveWriteInspector struct {
	BlockedDomain string
}

func (insp *NaiveWriteInspector) DetectsBlockedSNI(writes [][]byte) bool {
	target := []byte(insp.BlockedDomain)
	for _, chunk := range writes {
		if bytes.Contains(chunk, target) {
			return true
		}
	}
	return false
}

// RecordLayerInspector inspects individual TLS records without reassembling the logical handshake.
type RecordLayerInspector struct {
	BlockedDomain string
}

func (insp *RecordLayerInspector) DetectsBlockedSNI(stream []byte) bool {
	target := []byte(insp.BlockedDomain)
	offset := 0
	for offset+5 <= len(stream) {
		cType := stream[offset]
		payloadLen := int(stream[offset+3])<<8 | int(stream[offset+4])
		totalLen := 5 + payloadLen
		if offset+totalLen > len(stream) {
			break
		}
		if cType == 0x16 { // Handshake record
			recordPayload := stream[offset+5 : offset+totalLen]
			if bytes.Contains(recordPayload, target) {
				return true
			}
		}
		offset += totalLen
	}
	return false
}

// StreamReassemblingInspector models a stateful middlebox that reassembles TCP streams
// and reconstructs the full logical TLS ClientHello across records.
type StreamReassemblingInspector struct {
	BlockedDomain string
}

func (insp *StreamReassemblingInspector) DetectsBlockedSNI(stream []byte) bool {
	res := tlsparse.ParseClientHello(stream, tlsparse.DefaultLimits())
	if res.Status == tlsparse.StatusParsed && res.Metadata != nil && res.Metadata.HasSNI {
		return strings.EqualFold(res.Metadata.SNI, insp.BlockedDomain)
	}
	return false
}

func TestSimulatedDPIInspectionModels(t *testing.T) {
	blockedDomain := "censored.example.org"
	raw := buildSyntheticClientHello(blockedDomain)
	parseRes := tlsparse.ParseClientHello(raw, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed {
		t.Fatalf("failed to parse synthetic ClientHello: %s", parseRes.Status)
	}

	writeInspector := &NaiveWriteInspector{BlockedDomain: blockedDomain}
	recordInspector := &RecordLayerInspector{BlockedDomain: blockedDomain}
	streamInspector := &StreamReassemblingInspector{BlockedDomain: blockedDomain}

	// 1. Baseline `none`: All 3 inspectors detect the blocked SNI
	t.Run("none_baseline", func(t *testing.T) {
		strat := NewNoneStrategy()
		plan, _ := strat.Plan(context.Background(), raw, parseRes.Metadata)
		rec := &recordingMockWriter{}
		_, _ = Execute(context.Background(), rec, plan)

		if !writeInspector.DetectsBlockedSNI(rec.writes) {
			t.Fatal("expected NaiveWriteInspector to detect SNI in baseline none")
		}
		if !recordInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected RecordLayerInspector to detect SNI in baseline none")
		}
		if !streamInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected StreamReassemblingInspector to detect SNI in baseline none")
		}
	})

	// 2. `tcp-write-split` with `sni-mid`:
	// Bypasses NaiveWriteInspector (because the hostname string is sliced across 2 socket writes).
	// But FAILS to bypass RecordLayerInspector and StreamReassemblingInspector!
	t.Run("tcp_write_split", func(t *testing.T) {
		strat := NewTCPWriteSplitStrategy("sni-mid", 0)
		plan, _ := strat.Plan(context.Background(), raw, parseRes.Metadata)
		rec := &recordingMockWriter{}
		_, _ = Execute(context.Background(), rec, plan)

		if writeInspector.DetectsBlockedSNI(rec.writes) {
			t.Fatal("expected NaiveWriteInspector to miss split SNI across writes")
		}
		if !recordInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected RecordLayerInspector to detect SNI within the single TLS record")
		}
		if !streamInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected StreamReassemblingInspector to detect SNI in reassembled stream")
		}
	})

	// 3. `tls-record-split` with `sni-mid`:
	// Bypasses RecordLayerInspector (because the hostname string is sliced across 2 TLS records).
	// But FAILS to bypass StreamReassemblingInspector!
	t.Run("tls_record_split", func(t *testing.T) {
		strat := NewTLSRecordSplitStrategy("sni-mid")
		plan, _ := strat.Plan(context.Background(), raw, parseRes.Metadata)
		rec := &recordingMockWriter{}
		_, _ = Execute(context.Background(), rec, plan)

		if recordInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected RecordLayerInspector to miss SNI fragmented across records")
		}
		if !streamInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("StreamReassemblingInspector MUST detect SNI after TLS record reassembly")
		}
	})

	// 4. Composite `tls-record-then-write-split`:
	// Bypasses both NaiveWriteInspector AND RecordLayerInspector!
	// Still detected by StreamReassemblingInspector!
	t.Run("composite_record_and_write_split", func(t *testing.T) {
		strat := NewCompositeRecordThenWriteSplitStrategy("sni-mid", "sni-mid", 0)
		plan, _ := strat.Plan(context.Background(), raw, parseRes.Metadata)
		rec := &recordingMockWriter{}
		_, _ = Execute(context.Background(), rec, plan)

		if writeInspector.DetectsBlockedSNI(rec.writes) {
			t.Fatal("expected NaiveWriteInspector to miss SNI fragmented across writes")
		}
		if recordInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("expected RecordLayerInspector to miss SNI fragmented across records")
		}
		if !streamInspector.DetectsBlockedSNI(rec.ConcatenatedBytes()) {
			t.Fatal("StreamReassemblingInspector MUST detect SNI in full reconstructed stream")
		}
	})
}

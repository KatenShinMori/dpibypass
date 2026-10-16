package tlsparse

import (
	"testing"
)

func FuzzParseClientHello(f *testing.F) {
	// Seed corpus with synthetic valid, fragmented, and boundary-case fixtures
	seeds := [][]byte{
		wrapInSingleRecord(buildSyntheticClientHello("example.com", nil)),
		wrapInSingleRecord(buildSyntheticClientHello("", nil)),
		wrapInSingleRecord(buildSyntheticClientHello("ExAmPLe.CoM", nil)),
		wrapInFragmentedRecords(buildSyntheticClientHello("fragmented.example.org", nil), 50),
		wrapInSingleRecord(append(buildSyntheticClientHello("trailing.com", nil), []byte{0x00, 0x01, 0x02}...)),
		{0x16, 0x03, 0x01},                      // Incomplete record header
		{0x16, 0x03, 0x01, 0x00, 0x20},          // Record header with missing payload
		{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0}, // Alert record
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		{0x05, 0x01, 0x00}, // SOCKS5 greeting
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	limits := DefaultLimits()

	f.Fuzz(func(t *testing.T, data []byte) {
		res := ParseClientHello(data, limits)

		switch res.Status {
		case StatusParsed:
			if res.Metadata == nil {
				t.Fatalf("StatusParsed returned nil Metadata")
			}
			m := res.Metadata

			// Invariant 1: Handshake length bounds
			if m.LogicalHandshakeLength <= 4 {
				t.Fatalf("LogicalHandshakeLength %d must be > 4", m.LogicalHandshakeLength)
			}

			// Invariant 2: Logical SNI offsets strictly within LogicalHandshakeLength
			if m.HasSNI {
				if m.LogicalSNIOffsetStart < 4 ||
					m.LogicalSNIOffsetStart >= m.LogicalSNIOffsetEnd ||
					m.LogicalSNIOffsetEnd > m.LogicalHandshakeLength {
					t.Fatalf("SNI offsets [%d, %d] exceed LogicalHandshakeLength %d",
						m.LogicalSNIOffsetStart, m.LogicalSNIOffsetEnd, m.LogicalHandshakeLength)
				}
				if len(m.SNI) != (m.LogicalSNIOffsetEnd - m.LogicalSNIOffsetStart) {
					t.Fatalf("SNI string length %d != offset span %d",
						len(m.SNI), m.LogicalSNIOffsetEnd-m.LogicalSNIOffsetStart)
				}
			} else {
				if m.LogicalSNIOffsetStart != 0 || m.LogicalSNIOffsetEnd != 0 || m.SNI != "" {
					t.Fatalf("HasSNI=false but SNI fields non-zero")
				}
			}

			// Invariant 3: Wire offsets strictly within input data
			if m.ConsumedWireBytes <= 0 || m.ConsumedWireBytes > len(data) {
				t.Fatalf("ConsumedWireBytes %d out of bounds (len=%d)", m.ConsumedWireBytes, len(data))
			}
			if len(m.Records) == 0 {
				t.Fatalf("StatusParsed must have at least one record")
			}
			if m.IsFragmented != (len(m.Records) > 1) {
				t.Fatalf("IsFragmented (%v) inconsistent with record count (%d)", m.IsFragmented, len(m.Records))
			}

			// Invariant 4: Reconstructed logical handshake matches Metadata length and SNI slice
			reconstructed := reconstructLogicalHandshake(data, m.Records)
			if len(reconstructed) != m.LogicalHandshakeLength {
				t.Fatalf("reconstructed logical length %d != Metadata LogicalHandshakeLength %d",
					len(reconstructed), m.LogicalHandshakeLength)
			}
			if m.HasSNI {
				extractedSNI := string(reconstructed[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
				if extractedSNI != m.SNI {
					t.Fatalf("extracted SNI from reconstructed bytes %q != Metadata.SNI %q",
						extractedSNI, m.SNI)
				}
			}

			for i, r := range m.Records {
				recTotal := r.WireOffset + r.HeaderLen + r.PayloadLen
				if r.WireOffset < 0 || recTotal > len(data) {
					t.Fatalf("record %d [%d, %d] exceeds input len %d", i, r.WireOffset, recTotal, len(data))
				}
				if r.PayloadConsumed < 0 || r.PayloadConsumed > r.PayloadLen {
					t.Fatalf("record %d PayloadConsumed %d out of bounds (PayloadLen=%d)", i, r.PayloadConsumed, r.PayloadLen)
				}
				if r.PayloadRemaining < 0 || r.PayloadRemaining > r.PayloadLen {
					t.Fatalf("record %d PayloadRemaining %d out of bounds (PayloadLen=%d)", i, r.PayloadRemaining, r.PayloadLen)
				}
				if r.PayloadConsumed+r.PayloadRemaining != r.PayloadLen {
					t.Fatalf("record %d Consumed (%d) + Remaining (%d) != PayloadLen (%d)",
						i, r.PayloadConsumed, r.PayloadRemaining, r.PayloadLen)
				}
			}

			lastRec := m.Records[len(m.Records)-1]
			expectedConsumedWire := lastRec.WireOffset + lastRec.HeaderLen + lastRec.PayloadConsumed
			if m.ConsumedWireBytes != expectedConsumedWire {
				t.Fatalf("ConsumedWireBytes %d != expected %d", m.ConsumedWireBytes, expectedConsumedWire)
			}
			expectedTrailing := lastRec.PayloadRemaining > 0 || len(data) > m.ConsumedWireBytes
			if m.HasTrailingData != expectedTrailing {
				t.Fatalf("HasTrailingData (%v) != expected (%v)", m.HasTrailingData, expectedTrailing)
			}

		case StatusNeedMoreData:
			if res.Metadata != nil {
				t.Fatalf("StatusNeedMoreData must have nil Metadata")
			}
			if res.BytesNeeded <= 0 {
				t.Fatalf("StatusNeedMoreData must have positive BytesNeeded, got %d", res.BytesNeeded)
			}

		case StatusNotTLS, StatusNotClientHello, StatusMalformed, StatusLimitExceeded:
			if res.Metadata != nil {
				t.Fatalf("failure status %v must have nil Metadata", res.Status)
			}
			if res.BytesNeeded != 0 {
				t.Fatalf("failure status %v must have zero BytesNeeded, got %d", res.Status, res.BytesNeeded)
			}
			if res.Reason == "" {
				t.Fatalf("failure status %v must have non-empty Reason", res.Status)
			}
		}
	})
}

package tlsparse

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseClientHelloTable(t *testing.T) {
	limits := DefaultLimits()

	t.Run("valid standard SNI", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("example.com", nil)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Metadata == nil {
			t.Fatal("expected non-nil Metadata")
		}
		m := res.Metadata
		if !m.HasSNI || m.SNI != "example.com" {
			t.Errorf("expected SNI 'example.com', got %q (hasSNI=%v)", m.SNI, m.HasSNI)
		}
		if m.IsFragmented {
			t.Errorf("expected IsFragmented=false")
		}
		if m.ConsumedWireBytes != len(wire) {
			t.Errorf("expected ConsumedWireBytes=%d, got %d", len(wire), m.ConsumedWireBytes)
		}
		if m.LogicalHandshakeLength != len(rawHandshake) {
			t.Errorf("expected LogicalHandshakeLength=%d, got %d", len(rawHandshake), m.LogicalHandshakeLength)
		}

		// Exact slice verification
		extracted := string(rawHandshake[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
		if extracted != "example.com" {
			t.Errorf("logical offset slice mismatch: got %q, expected 'example.com'", extracted)
		}
	})

	t.Run("valid mixed-case SNI preserved exactly", func(t *testing.T) {
		const rawSpelling = "ExAmPLe.CoM"
		rawHandshake := buildSyntheticClientHello(rawSpelling, nil)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v", res.Status)
		}
		if res.Metadata.SNI != rawSpelling {
			t.Errorf("expected raw spelling %q preserved, got %q", rawSpelling, res.Metadata.SNI)
		}
	})

	t.Run("valid without SNI", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("", nil)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if m.HasSNI {
			t.Errorf("expected HasSNI=false, got true (SNI=%q)", m.SNI)
		}
		if m.SNI != "" {
			t.Errorf("expected empty SNI, got %q", m.SNI)
		}
		if m.LogicalSNIOffsetStart != 0 || m.LogicalSNIOffsetEnd != 0 {
			t.Errorf("expected zero offsets, got start=%d end=%d", m.LogicalSNIOffsetStart, m.LogicalSNIOffsetEnd)
		}
	})

	t.Run("valid fragmented across 2 records", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("fragmented.example.org", nil)
		splitPoint := len(rawHandshake) / 2
		wire := wrapInFragmentedRecords(rawHandshake, splitPoint)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if !m.IsFragmented {
			t.Errorf("expected IsFragmented=true")
		}
		if len(m.Records) != 2 {
			t.Fatalf("expected 2 records, got %d", len(m.Records))
		}
		if m.SNI != "fragmented.example.org" {
			t.Errorf("expected SNI 'fragmented.example.org', got %q", m.SNI)
		}
		if m.ConsumedWireBytes != len(wire) {
			t.Errorf("expected ConsumedWireBytes=%d, got %d", len(wire), m.ConsumedWireBytes)
		}

		reconstructed := reconstructLogicalHandshake(wire, m.Records)
		if len(reconstructed) != m.LogicalHandshakeLength {
			t.Errorf("expected logical len %d, got %d", m.LogicalHandshakeLength, len(reconstructed))
		}
		extracted := string(reconstructed[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
		if extracted != "fragmented.example.org" {
			t.Errorf("reconstructed SNI slice mismatch: got %q, expected 'fragmented.example.org'", extracted)
		}
	})

	t.Run("valid fragmented with SNI hostname split across records", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("splithostname.example.com", nil)
		// Find where "splithostname" starts and split in the middle of it
		targetStr := "splithostname.example.com"
		idx := bytes.Index(rawHandshake, []byte(targetStr))
		if idx == -1 {
			t.Fatal("target string not found in raw handshake")
		}
		splitPoint := idx + 5 // split inside "splithostname"
		wire := wrapInFragmentedRecords(rawHandshake, splitPoint)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if m.SNI != targetStr {
			t.Errorf("expected SNI %q, got %q", targetStr, m.SNI)
		}
		if !m.IsFragmented {
			t.Errorf("expected IsFragmented=true")
		}

		reconstructed := reconstructLogicalHandshake(wire, m.Records)
		extracted := string(reconstructed[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
		if extracted != targetStr {
			t.Errorf("reconstructed SNI slice mismatch: got %q, expected %q", extracted, targetStr)
		}
	})

	t.Run("valid handshake header split across records", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("splitheader.example.com", nil)
		// Split at byte 2 of the 4-byte handshake header!
		splitPoint := 2
		wire := wrapInFragmentedRecords(rawHandshake, splitPoint)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if m.SNI != "splitheader.example.com" {
			t.Errorf("expected SNI 'splitheader.example.com', got %q", m.SNI)
		}

		reconstructed := reconstructLogicalHandshake(wire, m.Records)
		extracted := string(reconstructed[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
		if extracted != "splitheader.example.com" {
			t.Errorf("reconstructed SNI slice mismatch: got %q, expected 'splitheader.example.com'", extracted)
		}
	})

	t.Run("valid trailing handshake data in same record", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("trailing.example.com", nil)
		trailingData := []byte{0x0b, 0x00, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee} // dummy handshake bytes

		combinedPayload := append(rawHandshake, trailingData...)
		wire := wrapInSingleRecord(combinedPayload)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if !m.HasTrailingData {
			t.Errorf("expected HasTrailingData=true")
		}
		if len(m.Records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(m.Records))
		}
		rec := m.Records[0]
		if rec.PayloadConsumed != len(rawHandshake) {
			t.Errorf("expected PayloadConsumed=%d, got %d", len(rawHandshake), rec.PayloadConsumed)
		}
		if rec.PayloadRemaining != len(trailingData) {
			t.Errorf("expected PayloadRemaining=%d, got %d", len(trailingData), rec.PayloadRemaining)
		}
		expectedConsumedWire := 5 + len(rawHandshake)
		if m.ConsumedWireBytes != expectedConsumedWire {
			t.Errorf("expected ConsumedWireBytes=%d, got %d", expectedConsumedWire, m.ConsumedWireBytes)
		}

		// Exact slice verification for intra-record trailing data
		intraTrailing := wire[rec.WireOffset+rec.HeaderLen+rec.PayloadConsumed : rec.WireOffset+rec.HeaderLen+rec.PayloadLen]
		if !bytes.Equal(intraTrailing, trailingData) {
			t.Errorf("intra-record trailing bytes mismatch: got %x, expected %x", intraTrailing, trailingData)
		}
		if !bytes.Equal(wire[m.ConsumedWireBytes:], trailingData) {
			t.Errorf("wire trailing bytes mismatch: got %x, expected %x", wire[m.ConsumedWireBytes:], trailingData)
		}
	})

	t.Run("valid trailing data after complete record", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("trailingwire.example.com", nil)
		wire := wrapInSingleRecord(rawHandshake)
		extraWire := append(wire, []byte("EXTRA_TRAILING_BYTES")...)

		res := ParseClientHello(extraWire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if !m.HasTrailingData {
			t.Errorf("expected HasTrailingData=true")
		}
		if m.ConsumedWireBytes != len(wire) {
			t.Errorf("expected ConsumedWireBytes=%d, got %d", len(wire), m.ConsumedWireBytes)
		}
		trailingWire := extraWire[m.ConsumedWireBytes:]
		if !bytes.Equal(trailingWire, []byte("EXTRA_TRAILING_BYTES")) {
			t.Errorf("trailing wire mismatch: got %q, expected 'EXTRA_TRAILING_BYTES'", string(trailingWire))
		}
	})

	t.Run("valid ClientHello with large collection of 12 distinct extensions", func(t *testing.T) {
		extraExts := map[uint16][]byte{
			0x0005: {0x01, 0x00, 0x00, 0x00, 0x00},                                             // status_request
			0x000a: {0x00, 0x04, 0x00, 0x1d, 0x00, 0x17},                                       // supported_groups
			0x000b: {0x01, 0x00},                                                               // ec_point_formats
			0x000d: {0x00, 0x04, 0x04, 0x03, 0x08, 0x04},                                       // signature_algorithms
			0x0010: {0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}, // alpn
			0x0012: {},                                                                         // signed_certificate_timestamp
			0x0015: bytes.Repeat([]byte{0x00}, 64),                                             // padding
			0x0017: {},                                                                         // extended_master_secret
			0x002b: {0x02, 0x03, 0x04},                                                         // supported_versions
			0x002d: {0x01, 0x01},                                                               // psk_key_exchange_modes
			0x0033: {0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04},               // key_share
			0xff01: {0x00},                                                                     // renegotiation_info
		}
		const targetSNI = "large-ext.example.com"
		rawHandshake := buildSyntheticClientHello(targetSNI, extraExts)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusParsed {
			t.Fatalf("expected StatusParsed, got %v (reason: %s)", res.Status, res.Reason)
		}
		m := res.Metadata
		if !m.HasSNI || m.SNI != targetSNI {
			t.Errorf("expected SNI %q, got %q (hasSNI=%v)", targetSNI, m.SNI, m.HasSNI)
		}
		reconstructed := reconstructLogicalHandshake(wire, m.Records)
		extracted := string(reconstructed[m.LogicalSNIOffsetStart:m.LogicalSNIOffsetEnd])
		if extracted != targetSNI {
			t.Errorf("logical offset extracted %q != %q", extracted, targetSNI)
		}
		if m.ConsumedWireBytes != len(wire) {
			t.Errorf("expected ConsumedWireBytes=%d, got %d", len(wire), m.ConsumedWireBytes)
		}
	})
}

func TestParseClientHelloIncomplete(t *testing.T) {
	limits := DefaultLimits()

	t.Run("incomplete record header 1 to 4 bytes", func(t *testing.T) {
		for size := 1; size < 5; size++ {
			raw := []byte{0x16, 0x03, 0x01, 0x00}[:size]
			res := ParseClientHello(raw, limits)
			if res.Status != StatusNeedMoreData {
				t.Errorf("for size %d: expected StatusNeedMoreData, got %v", size, res.Status)
			}
			expectedNeeded := 5 - size
			if res.BytesNeeded != expectedNeeded {
				t.Errorf("for size %d: expected BytesNeeded=%d, got %d", size, expectedNeeded, res.BytesNeeded)
			}
		}
	})

	t.Run("incomplete record payload", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("incomplete.example.com", nil)
		wire := wrapInSingleRecord(rawHandshake)

		// Provide full 5-byte header + half the payload
		truncatedWire := wire[:5+(len(rawHandshake)/2)]
		res := ParseClientHello(truncatedWire, limits)
		if res.Status != StatusNeedMoreData {
			t.Fatalf("expected StatusNeedMoreData, got %v", res.Status)
		}
		expectedNeeded := len(wire) - len(truncatedWire)
		if res.BytesNeeded != expectedNeeded {
			t.Errorf("expected BytesNeeded=%d, got %d", expectedNeeded, res.BytesNeeded)
		}
	})

	t.Run("incomplete second record header in fragmented handshake", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("fragincomplete.example.com", nil)
		splitPoint := len(rawHandshake) / 2
		wire := wrapInFragmentedRecords(rawHandshake, splitPoint)

		// Record 1 wire len = 5 + splitPoint
		rec1WireLen := 5 + splitPoint
		// Truncate to record 1 + 2 bytes of record 2's header
		truncatedWire := wire[:rec1WireLen+2]

		res := ParseClientHello(truncatedWire, limits)
		if res.Status != StatusNeedMoreData {
			t.Fatalf("expected StatusNeedMoreData, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.BytesNeeded != 3 { // 5 - 2 = 3 bytes needed for record 2 header
			t.Errorf("expected BytesNeeded=3, got %d", res.BytesNeeded)
		}
	})

	t.Run("incomplete handshake header in record payload", func(t *testing.T) {
		// Record has 5-byte header, but only 2 bytes payload (less than the 4-byte handshake header)
		rec := []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}
		res := ParseClientHello(rec, limits)
		if res.Status != StatusNeedMoreData {
			t.Fatalf("expected StatusNeedMoreData, got %v", res.Status)
		}
		if res.BytesNeeded != 5 {
			t.Errorf("expected BytesNeeded=5 (next record header), got %d", res.BytesNeeded)
		}
	})

	t.Run("incomplete handshake body across records with only first record provided", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("tworecords.example.com", nil)
		splitPoint := len(rawHandshake) / 2
		wire := wrapInFragmentedRecords(rawHandshake, splitPoint)

		rec1Len := 5 + splitPoint
		onlyRec1 := wire[:rec1Len]

		res := ParseClientHello(onlyRec1, limits)
		if res.Status != StatusNeedMoreData {
			t.Fatalf("expected StatusNeedMoreData, got %v", res.Status)
		}
		if res.BytesNeeded != 5 {
			t.Errorf("expected BytesNeeded=5 (next record header), got %d", res.BytesNeeded)
		}
		if res.Reason != "next_record_header_needed" {
			t.Errorf("expected reason 'next_record_header_needed', got %q", res.Reason)
		}
	})
}

func TestParseClientHelloMalformedAndLimits(t *testing.T) {
	limits := DefaultLimits()

	t.Run("duplicate SNI extension rejected", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("dup.example.com", map[uint16][]byte{
			0x0000: {0x00, 0x05, 0x00, 0x00, 0x02, 'a', 'b'}, // Duplicate extension type 0x0000
		})
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed for duplicate extension, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "duplicate_extension" {
			t.Errorf("expected reason 'duplicate_extension', got %q", res.Reason)
		}
	})

	t.Run("malformed session id length", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("example.com", nil)
		// Byte 38 is SessionID length; corrupt it to 200 (overruns body)
		rawHandshake[38] = 200
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v", res.Status)
		}
	})

	t.Run("malformed cipher suites length odd", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("example.com", nil)
		// Cipher suites length is at index 39: corrupt to 3 (odd number of bytes)
		rawHandshake[39] = 0x00
		rawHandshake[40] = 0x03
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v", res.Status)
		}
	})

	t.Run("malformed extension-vector length exceeds body", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("example.com", nil)
		// Extensions block starts after compression methods at index 47.
		// 47..49 is the 2-byte extensions length.
		rawHandshake[47] = 0x13
		rawHandshake[48] = 0x88 // 5000 bytes
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "extensions_vector_length_mismatch" {
			t.Errorf("expected reason 'extensions_vector_length_mismatch', got %q", res.Reason)
		}
	})

	t.Run("malformed individual extension length exceeds extensions block", func(t *testing.T) {
		rawHandshake := buildSyntheticClientHello("example.com", nil)
		// First extension header: extType at 49..51 (0x0000 SNI), extLen at 51..53.
		// Corrupt extLen to 500 bytes.
		rawHandshake[51] = 0x01
		rawHandshake[52] = 0xf4
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "extension_length_out_of_bounds" {
			t.Errorf("expected reason 'extension_length_out_of_bounds', got %q", res.Reason)
		}
	})

	t.Run("malformed SNI list length truncated", func(t *testing.T) {
		customSNI := map[uint16][]byte{
			0x0000: {0x00, 0x01, 0x00}, // listLen 1, invalid (must be >= 3 and match extLen-2)
		}
		rawHandshake := buildSyntheticClientHello("", customSNI)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "sni_list_length_mismatch" {
			t.Errorf("expected reason 'sni_list_length_mismatch', got %q", res.Reason)
		}
	})

	t.Run("malformed SNI hostname length exceeds list", func(t *testing.T) {
		sniPayload := []byte{0x00, 0x08, 0x00, 0x00, 0x14, 'a', 'b', 'c', 'd', 'e'}
		customSNI := map[uint16][]byte{
			0x0000: sniPayload,
		}
		rawHandshake := buildSyntheticClientHello("", customSNI)
		wire := wrapInSingleRecord(rawHandshake)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusMalformed {
			t.Fatalf("expected StatusMalformed, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "sni_hostname_out_of_bounds" {
			t.Errorf("expected reason 'sni_hostname_out_of_bounds', got %q", res.Reason)
		}
	})

	t.Run("oversized record payload exceeds 16384 limit", func(t *testing.T) {
		header := make([]byte, 5)
		header[0] = 0x16
		binary.BigEndian.PutUint16(header[1:3], 0x0301)
		binary.BigEndian.PutUint16(header[3:5], 20000) // 20000 > 16384

		res := ParseClientHello(header, limits)
		if res.Status != StatusLimitExceeded {
			t.Fatalf("expected StatusLimitExceeded, got %v (reason: %s)", res.Status, res.Reason)
		}
	})

	t.Run("oversized declared handshake length exceeds MaxHandshakeBytes", func(t *testing.T) {
		recPayload := []byte{
			0x01,             // HandshakeType: ClientHello
			0x00, 0x9c, 0x40, // Length 40,000 (0x009c40) > MaxHandshakeBytes (32,768)
			0x03, 0x03, // Version
		}
		wire := wrapInSingleRecord(recPayload)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusLimitExceeded {
			t.Fatalf("expected StatusLimitExceeded, got %v (reason: %s)", res.Status, res.Reason)
		}
		if res.Reason != "handshake_size_exceeds_limit" {
			t.Errorf("expected reason 'handshake_size_exceeds_limit', got %q", res.Reason)
		}
	})

	t.Run("not TLS initial byte", func(t *testing.T) {
		httpGet := []byte("GET / HTTP/1.1\r\n\r\n")
		res := ParseClientHello(httpGet, limits)
		if res.Status != StatusNotTLS {
			t.Fatalf("expected StatusNotTLS, got %v", res.Status)
		}
	})

	t.Run("not TLS unsupported major version", func(t *testing.T) {
		invalidVer := []byte{0x16, 0x04, 0x00, 0x00, 0x10}
		res := ParseClientHello(invalidVer, limits)
		if res.Status != StatusNotTLS {
			t.Fatalf("expected StatusNotTLS, got %v", res.Status)
		}
	})

	t.Run("unsupported outer record version 0x0304 (TLS 1.3)", func(t *testing.T) {
		tls13Outer := []byte{0x16, 0x03, 0x04, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
		res := ParseClientHello(tls13Outer, limits)
		if res.Status != StatusNotTLS {
			t.Fatalf("expected StatusNotTLS, got %v", res.Status)
		}
		if res.Reason != "unsupported_record_version_0x0304" {
			t.Errorf("expected reason 'unsupported_record_version_0x0304', got %q", res.Reason)
		}
	})

	t.Run("unsupported outer record version 0x0200 (SSL 2.0)", func(t *testing.T) {
		ssl2Outer := []byte{0x16, 0x02, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
		res := ParseClientHello(ssl2Outer, limits)
		if res.Status != StatusNotTLS {
			t.Fatalf("expected StatusNotTLS, got %v", res.Status)
		}
		if res.Reason != "unsupported_record_version_0x0200" {
			t.Errorf("expected reason 'unsupported_record_version_0x0200', got %q", res.Reason)
		}
	})

	t.Run("not ClientHello: ServerHello handshake type", func(t *testing.T) {
		serverHello := []byte{
			0x02,             // HandshakeType: ServerHello
			0x00, 0x00, 0x04, // Length 4
			0x03, 0x03, 0xaa, 0xbb, // Body
		}
		wire := wrapInSingleRecord(serverHello)

		res := ParseClientHello(wire, limits)
		if res.Status != StatusNotClientHello {
			t.Fatalf("expected StatusNotClientHello, got %v (reason: %s)", res.Status, res.Reason)
		}
	})

	t.Run("not ClientHello: Alert record type", func(t *testing.T) {
		alertRec := []byte{
			0x15,       // ContentType: Alert
			0x03, 0x01, // Version
			0x00, 0x02, // Length 2
			0x02, 0x28, // fatal, handshake failure
		}

		res := ParseClientHello(alertRec, limits)
		if res.Status != StatusNotClientHello {
			t.Fatalf("expected StatusNotClientHello, got %v (reason: %s)", res.Status, res.Reason)
		}
	})
}

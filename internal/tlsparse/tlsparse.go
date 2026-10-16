package tlsparse

import (
	"fmt"
)

// Status represents the parsing classification of the supplied byte buffer.
type Status int

const (
	// StatusNeedMoreData indicates the input is a valid TLS prefix so far,
	// but additional bytes are needed to complete the current record header,
	// record payload, or logical handshake message.
	StatusNeedMoreData Status = iota

	// StatusParsed indicates a complete, structurally valid ClientHello was parsed.
	StatusParsed

	// StatusNotTLS indicates the initial bytes do not match TLS record framing
	// (e.g. ContentType is not recognized TLS, or major version != 0x03).
	StatusNotTLS

	// StatusNotClientHello indicates a valid TLS record was detected,
	// but it is not a ClientHello (e.g. ContentType is Alert, ChangeCipherSpec,
	// or Handshake with message type != 0x01).
	StatusNotClientHello

	// StatusMalformed indicates structurally invalid TLS data
	// (e.g. inconsistent vector lengths, duplicate extensions, invalid extension bounds).
	StatusMalformed

	// StatusLimitExceeded indicates declared record size, aggregate buffer,
	// or handshake length exceeds configured safety limits.
	StatusLimitExceeded
)

func (s Status) String() string {
	switch s {
	case StatusNeedMoreData:
		return "need_more_data"
	case StatusParsed:
		return "parsed"
	case StatusNotTLS:
		return "not_tls"
	case StatusNotClientHello:
		return "not_client_hello"
	case StatusMalformed:
		return "malformed"
	case StatusLimitExceeded:
		return "limit_exceeded"
	default:
		return fmt.Sprintf("status_%d", int(s))
	}
}

// ParserLimits defines conservative bounds to prevent unbounded memory allocation or infinite parsing.
type ParserLimits struct {
	// MaxRecordPayloadBytes is the maximum allowed value in a TLS record's 16-bit length field.
	// RFC 5246 Section 6.2.1 / RFC 8446 Section 5.1 limit plaintext fragments to 2^14 = 16384 bytes.
	MaxRecordPayloadBytes int

	// MaxWireRecordBytes is the maximum wire length of a single record (5-byte header + payload).
	// Default: 5 + 16384 = 16389 bytes.
	MaxWireRecordBytes int

	// MaxHandshakeBytes is the maximum allowed logical handshake message length (header + body).
	// Default: 32768 (32 KB).
	MaxHandshakeBytes int

	// MaxAggregateBuffer is the maximum size of raw input to inspect.
	// Default: 65536 (64 KB).
	MaxAggregateBuffer int

	// MaxRecordCount is the maximum number of consecutive records scanned for a single handshake.
	// Default: 16.
	MaxRecordCount int
}

// DefaultLimits returns conservative, RFC-compliant bounds for TLS parsing.
func DefaultLimits() ParserLimits {
	return ParserLimits{
		MaxRecordPayloadBytes: 16384,
		MaxWireRecordBytes:    16389,
		MaxHandshakeBytes:     32768,
		MaxAggregateBuffer:    65536,
		MaxRecordCount:        16,
	}
}

// RecordBoundary tracks the physical wire location and framing of an individual TLS record.
type RecordBoundary struct {
	WireOffset       int    // Start index in the supplied raw input slice
	HeaderLen        int    // Record header length (always 5 bytes)
	PayloadLen       int    // Declared payload length from the 16-bit record header
	PayloadConsumed  int    // Bytes of this record's payload consumed by the ClientHello
	PayloadRemaining int    // Bytes of this record's payload remaining after the ClientHello
	Version          uint16 // Legacy record version (e.g. 0x0301, 0x0303)
	ContentType      byte   // TLS record content type (0x16 for Handshake)
}

// ClientHelloMetadata contains validated structural metadata from a parsed ClientHello.
type ClientHelloMetadata struct {
	HasSNI             bool
	SNI                string // Raw ServerName string exactly as spelled on wire (un-normalized)
	LegacyVersion      uint16
	CipherSuites       []uint16
	CompressionMethods []byte

	// Logical Handshake representation:
	// Logical offsets refer to reconstructed contiguous handshake bytes (starting at byte 0 with HandshakeType 0x01).
	LogicalHandshakeLength int // Total length of the logical handshake message (4-byte header + body)
	LogicalSNIOffsetStart  int // Start index of ServerName hostname in logical handshake
	LogicalSNIOffsetEnd    int // End index of ServerName hostname in logical handshake

	// Wire-level record structure:
	Records           []RecordBoundary // Ordered list of records comprising this ClientHello
	ConsumedWireBytes int              // Total wire bytes consumed up to the end of the ClientHello
	IsFragmented      bool             // True if the logical ClientHello spans > 1 TLS record
	HasTrailingData   bool             // True if trailing bytes exist in the final record or wire buffer
}

// ParseResult reports the parser's findings.
type ParseResult struct {
	Status      Status
	Metadata    *ClientHelloMetadata
	Reason      string
	BytesNeeded int // Minimum additional bytes needed to make the next parsing decision
}

// ParseClientHello analyzes raw input bytes and returns a ParseResult.
// It never panics, bounds all slicing, and leaves network accumulation/fallback policies to the caller.
func ParseClientHello(raw []byte, limits ParserLimits) ParseResult {
	if limits.MaxRecordPayloadBytes <= 0 {
		limits = DefaultLimits()
	}

	if len(raw) > limits.MaxAggregateBuffer {
		return ParseResult{
			Status: StatusLimitExceeded,
			Reason: "aggregate_buffer_exceeds_limit",
		}
	}

	return parseRecordsAndHandshake(raw, limits)
}

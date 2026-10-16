package strategy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"dpibypass/internal/tlsparse"
)

var (
	ErrNotSingleRecord         = errors.New("tls-record-split requires exactly one unfragmented TLS record")
	ErrCannotSplitAtOffset     = errors.New("cannot split TLS record at requested offset")
	ErrTrailingDataUnsupported = errors.New("tls-record-split does not support trailing record payload or data")
)

// TLSRecordSplitStrategy transforms a single TLS ClientHello record into two valid TLS handshake records.
// This is a protocol-level framing transformation, distinct from TCP socket write splitting.
type TLSRecordSplitStrategy struct {
	Offset string
}

// NewTLSRecordSplitStrategy constructs a TLSRecordSplitStrategy with a given offset specification.
func NewTLSRecordSplitStrategy(offset string) *TLSRecordSplitStrategy {
	if offset == "" {
		offset = "sni-mid"
	}
	return &TLSRecordSplitStrategy{
		Offset: offset,
	}
}

// Name returns the strategy identifier.
func (s *TLSRecordSplitStrategy) Name() string {
	return "tls-record-split"
}

// Plan evaluates preconditions, synthesizes two valid TLS records, re-validates the result using tlsparse,
// and produces an ExecutionPlan. If preconditions or validation fail, it falls back to the original unmodified bytes.
func (s *TLSRecordSplitStrategy) Plan(_ context.Context, input []byte, meta *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	if len(input) == 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       nil,
		}, nil
	}

	// Precondition 1: Metadata must indicate a parsed ClientHello
	if meta == nil {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "no_client_hello_metadata",
		}, nil
	}

	// Precondition 2: Must be an unfragmented single-record ClientHello starting at wire offset 0
	if meta.IsFragmented || len(meta.Records) != 1 || meta.Records[0].WireOffset != 0 || meta.Records[0].HeaderLen != 5 {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: ErrNotSingleRecord.Error(),
		}, nil
	}

	rec := meta.Records[0]
	handshakeLen := meta.LogicalHandshakeLength
	if handshakeLen < 4 {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "handshake_length_too_small",
		}, nil
	}

	// Handshake bytes begin at input[rec.WireOffset + rec.HeaderLen]
	handshakeStart := rec.WireOffset + rec.HeaderLen
	if handshakeStart+handshakeLen > len(input) {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "handshake_bytes_truncated_in_buffer",
		}, nil
	}

	// Precondition 3: The TLS record must not contain trailing payload bytes after the ClientHello,
	// and the input buffer must not contain unverified trailing bytes beyond the parsed ClientHello.
	// tlsparse does not provide framing information for trailing data; attempting transformation or
	// appending trailing bytes without reliable record framing would corrupt the TLS stream.
	if meta.HasTrailingData || rec.PayloadRemaining != 0 || rec.PayloadConsumed != handshakeLen || handshakeStart+handshakeLen < len(input) || meta.ConsumedWireBytes != len(input) {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: ErrTrailingDataUnsupported.Error(),
		}, nil
	}

	// Determine logical split point S within the logical handshake [0..handshakeLen)
	splitPoint, err := s.determineLogicalSplit(meta, handshakeLen)
	if err != nil {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: err.Error(),
		}, nil
	}

	logicalHandshake := input[handshakeStart : handshakeStart+handshakeLen]

	// Synthesize Record 1 and Record 2
	rec1Len := splitPoint
	rec2Len := handshakeLen - splitPoint

	if rec1Len <= 0 || rec2Len <= 0 || rec1Len > 16384 || rec2Len > 16384 {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "invalid_synthesized_record_lengths",
		}, nil
	}

	var transformed bytes.Buffer
	transformed.Grow(10 + handshakeLen)

	// Record 1 Header (5 bytes)
	var hdr1 [5]byte
	hdr1[0] = 0x16 // Handshake
	binary.BigEndian.PutUint16(hdr1[1:3], rec.Version)
	binary.BigEndian.PutUint16(hdr1[3:5], uint16(rec1Len))
	transformed.Write(hdr1[:])
	transformed.Write(logicalHandshake[:splitPoint])

	// Record 2 Header (5 bytes)
	var hdr2 [5]byte
	hdr2[0] = 0x16 // Handshake
	binary.BigEndian.PutUint16(hdr2[1:3], rec.Version)
	binary.BigEndian.PutUint16(hdr2[3:5], uint16(rec2Len))
	transformed.Write(hdr2[:])
	transformed.Write(logicalHandshake[splitPoint:])

	synthesizedBytes := transformed.Bytes()

	// Strict Re-Validation: Verify the synthesized records parse cleanly as a fragmented ClientHello
	reparseResult := tlsparse.ParseClientHello(synthesizedBytes, tlsparse.DefaultLimits())
	if reparseResult.Status != tlsparse.StatusParsed || reparseResult.Metadata == nil {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: fmt.Sprintf("revalidation_status_%s", reparseResult.Status),
		}, nil
	}

	if !reparseResult.Metadata.IsFragmented || len(reparseResult.Metadata.Records) != 2 {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "revalidation_records_mismatch",
		}, nil
	}

	// Verify reconstructed handshake length matches exactly
	if reparseResult.Metadata.LogicalHandshakeLength != handshakeLen {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "revalidation_handshake_length_mismatch",
		}, nil
	}

	// Verify synthesized output has no unparsed or trailing bytes
	if reparseResult.Metadata.HasTrailingData || reparseResult.Metadata.ConsumedWireBytes != len(synthesizedBytes) {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "revalidation_trailing_data_detected",
		}, nil
	}

	// Verify SNI consistency
	if reparseResult.Metadata.HasSNI != meta.HasSNI || reparseResult.Metadata.SNI != meta.SNI {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "revalidation_sni_mismatch",
		}, nil
	}

	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks: []WriteChunk{
			{
				Data:  synthesizedBytes,
				Delay: 0,
			},
		},
		IsFallback: false,
	}, nil
}

func (s *TLSRecordSplitStrategy) determineLogicalSplit(meta *tlsparse.ClientHelloMetadata, handshakeLen int) (int, error) {
	norm := strings.ToLower(strings.TrimSpace(s.Offset))
	if norm == "" {
		norm = "sni-mid"
	}

	switch norm {
	case "sni-start":
		if !meta.HasSNI {
			return 0, ErrSNINotPresent
		}
		if meta.LogicalSNIOffsetStart <= 0 || meta.LogicalSNIOffsetStart >= handshakeLen {
			return 0, ErrCannotSplitAtOffset
		}
		return meta.LogicalSNIOffsetStart, nil

	case "sni-mid":
		if !meta.HasSNI {
			// Fallback split in middle of handshake if SNI absent
			return handshakeLen / 2, nil
		}
		mid := (meta.LogicalSNIOffsetStart + meta.LogicalSNIOffsetEnd) / 2
		if mid <= 0 || mid >= handshakeLen {
			return 0, ErrCannotSplitAtOffset
		}
		return mid, nil

	case "sni-end":
		if !meta.HasSNI {
			return 0, ErrSNINotPresent
		}
		if meta.LogicalSNIOffsetEnd <= 0 || meta.LogicalSNIOffsetEnd >= handshakeLen {
			return 0, ErrCannotSplitAtOffset
		}
		return meta.LogicalSNIOffsetEnd, nil

	default:
		val, err := strconv.Atoi(norm)
		if err != nil {
			return 0, fmt.Errorf("%w: %q", ErrInvalidOffsetFormat, s.Offset)
		}
		if val <= 0 || val >= handshakeLen {
			return 0, fmt.Errorf("%w: offset %d out of bounds (1..%d)", ErrOffsetOutOfBounds, val, handshakeLen-1)
		}
		return val, nil
	}
}

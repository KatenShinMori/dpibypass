package strategy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"dpibypass/internal/tlsparse"
)

// BoundaryPlacement dictates how a split offset is resolved when it falls exactly on a TLS record boundary.
type BoundaryPlacement int

const (
	// PlacementBeforeRecordHeader places the split point before the record's 5-byte header.
	// Used for sni-start and sni-end so record headers are never sliced across chunks.
	PlacementBeforeRecordHeader BoundaryPlacement = iota

	// PlacementAfterRecordHeader places the split point after the record's 5-byte header.
	PlacementAfterRecordHeader
)

// Errors returned by wire mapping.
var (
	ErrSNINotPresent         = errors.New("sni hostname is not present in metadata")
	ErrInvalidOffsetFormat   = errors.New("invalid offset format")
	ErrOffsetOutOfBounds     = errors.New("calculated split offset is out of bounds")
	ErrAmbiguousRecordLayout = errors.New("record boundaries are ambiguous or incomplete for offset mapping")
)

// ResolveSplitOffset determines the raw wire offset for a given offset specification ("sni-start",
// "sni-mid", "sni-end", or a numeric string) based on raw input and parsed metadata.
// It enforces all record-boundary invariants and returns an error on any ambiguity.
func ResolveSplitOffset(raw []byte, meta *tlsparse.ClientHelloMetadata, offsetSpec string) (int, error) {
	if len(raw) == 0 {
		return 0, errors.New("empty raw data")
	}

	norm := strings.ToLower(strings.TrimSpace(offsetSpec))
	if norm == "" {
		norm = "sni-mid"
	}

	switch norm {
	case "sni-start":
		if meta == nil || !meta.HasSNI {
			return 0, ErrSNINotPresent
		}
		return LogicalToWireOffset(raw, meta, meta.LogicalSNIOffsetStart, PlacementBeforeRecordHeader)

	case "sni-mid":
		if meta == nil || !meta.HasSNI {
			return 0, ErrSNINotPresent
		}
		midLogical := (meta.LogicalSNIOffsetStart + meta.LogicalSNIOffsetEnd) / 2
		return LogicalToWireOffset(raw, meta, midLogical, PlacementBeforeRecordHeader)

	case "sni-end":
		if meta == nil || !meta.HasSNI {
			return 0, ErrSNINotPresent
		}
		return LogicalToWireOffset(raw, meta, meta.LogicalSNIOffsetEnd, PlacementBeforeRecordHeader)

	default:
		// Attempt parsing as fixed integer byte offset
		val, err := strconv.Atoi(norm)
		if err != nil {
			return 0, fmt.Errorf("%w: %q", ErrInvalidOffsetFormat, offsetSpec)
		}
		if val <= 0 || val >= len(raw) {
			return 0, fmt.Errorf("%w: numeric offset %d out of bounds (1..%d)", ErrOffsetOutOfBounds, val, len(raw)-1)
		}
		return val, nil
	}
}

// LogicalToWireOffset maps an offset within the reconstructed logical handshake message
// to an exact wire offset in raw, taking into account multi-record layouts and 5-byte TLS record headers.
func LogicalToWireOffset(
	raw []byte,
	meta *tlsparse.ClientHelloMetadata,
	logicalOffset int,
	placement BoundaryPlacement,
) (int, error) {
	if meta == nil || len(meta.Records) == 0 {
		return 0, ErrAmbiguousRecordLayout
	}
	if logicalOffset < 0 || logicalOffset > meta.LogicalHandshakeLength {
		return 0, fmt.Errorf("%w: logical offset %d exceeds handshake length %d", ErrOffsetOutOfBounds, logicalOffset, meta.LogicalHandshakeLength)
	}

	cumulativeLogical := 0
	for i, rec := range meta.Records {
		recPayloadEnd := cumulativeLogical + rec.PayloadConsumed

		// Case 1: logicalOffset is strictly inside this record's payload
		if logicalOffset > cumulativeLogical && logicalOffset < recPayloadEnd {
			payloadOffset := logicalOffset - cumulativeLogical
			wireOffset := rec.WireOffset + rec.HeaderLen + payloadOffset
			if wireOffset <= 0 || wireOffset >= len(raw) {
				return 0, fmt.Errorf("%w: wire offset %d exceeds buffer length %d", ErrOffsetOutOfBounds, wireOffset, len(raw))
			}
			return wireOffset, nil
		}

		// Case 2: logicalOffset lands exactly at the start of this record's logical slice
		if logicalOffset == cumulativeLogical {
			if i == 0 {
				// At start of handshake: splitting before record 0 header gives wire offset 0, which is invalid (chunk 0 empty)
				if placement == PlacementAfterRecordHeader {
					wireOffset := rec.WireOffset + rec.HeaderLen
					if wireOffset >= len(raw) {
						return 0, ErrOffsetOutOfBounds
					}
					return wireOffset, nil
				}
				// Default split right after record header if before header would be 0
				wireOffset := rec.WireOffset + rec.HeaderLen
				if wireOffset >= len(raw) {
					return 0, ErrOffsetOutOfBounds
				}
				return wireOffset, nil
			}

			// For i > 0, we are at the boundary between record i-1 and record i
			switch placement {
			case PlacementBeforeRecordHeader:
				// Split before record i's 5-byte header
				wireOffset := rec.WireOffset
				if wireOffset <= 0 || wireOffset >= len(raw) {
					return 0, ErrOffsetOutOfBounds
				}
				return wireOffset, nil
			case PlacementAfterRecordHeader:
				// Split after record i's 5-byte header
				wireOffset := rec.WireOffset + rec.HeaderLen
				if wireOffset <= 0 || wireOffset >= len(raw) {
					return 0, ErrOffsetOutOfBounds
				}
				return wireOffset, nil
			}
		}

		// Case 3: logicalOffset is at the end of the final record
		if logicalOffset == recPayloadEnd && i == len(meta.Records)-1 {
			// At end of handshake: wire offset is where payload ends
			wireOffset := rec.WireOffset + rec.HeaderLen + rec.PayloadConsumed
			if wireOffset >= len(raw) {
				return 0, fmt.Errorf("%w: split at end of buffer %d is invalid", ErrOffsetOutOfBounds, wireOffset)
			}
			return wireOffset, nil
		}

		cumulativeLogical = recPayloadEnd
	}

	return 0, ErrAmbiguousRecordLayout
}

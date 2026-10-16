package strategy

import (
	"context"
	"time"

	"dpibypass/internal/tlsparse"
)

// CompositeRecordThenWriteSplitStrategy composes TLS record splitting followed by application-level
// TCP socket write splitting.
//
// Stage 1 transforms the ClientHello into two valid TLS records split at RecordSplitOffset.
// Stage 2 partitions the resulting synthesized byte stream across discrete socket writes at WriteSplitOffset.
//
// Protocol & architectural boundaries:
//   - TLS record framing: TLS record-layer framing with discrete headers and lengths, partitioning logical handshake bytes across distinct valid TLS records.
//   - Application socket writes: Distinct net.Conn.Write calls issued from userspace separated by Delay.
//   - TCP segments: Socket write boundaries do not determine physical TCP segment boundaries on the wire.
//     Winsock buffering, Nagle algorithm / delayed ACKs, and NIC segmentation offloading (TSO/LSO) can reshape
//     segment boundaries independently.
//   - Middlebox inference caution: Observed handshake timeouts on external targets do not prove that an
//     intervening middlebox performed full TCP stream reassembly; failure may stem from silent packet drops,
//     SNI filtering, IP-level throttling, server-side policies, or other path behaviors.
//
// Write offset mapping across transformed TLS framing:
// Stage 1 inserts a second 5-byte TLS record header (0x16 0x03 ...) into the wire buffer, shifting
// wire positions relative to original logical handshake offsets.
// To preserve protocol correctness, Stage 2 reparses the synthesized multi-record stream with
// tlsparse.ParseClientHello to obtain updated RecordBoundary metadata.
//   - Logical offsets ("sni-start", "sni-mid", "sni-end"): Resolved via LogicalToWireOffset against the
//     reparsed multi-record metadata. LogicalToWireOffset tracks cumulative record payloads and shifts the
//     wire offset by the 5-byte header of each intervening record, ensuring the logical split point lands
//     on the exact intended handshake byte on the wire.
//   - Numeric offsets (e.g. "40"): Interpreted directly as serialized wire-buffer offsets into Stage 1's
//     synthesized multi-record output (bounded by 1..len(transformedBytes)-1).
//
// This strictly prevents conflation between logical handshake offsets and serialized wire-buffer offsets.
type CompositeRecordThenWriteSplitStrategy struct {
	RecordSplitOffset string
	WriteSplitOffset  string
	Delay             time.Duration
}

// NewCompositeRecordThenWriteSplitStrategy creates a validated composite strategy.
func NewCompositeRecordThenWriteSplitStrategy(recordOffset, writeOffset string, delay time.Duration) *CompositeRecordThenWriteSplitStrategy {
	if recordOffset == "" {
		recordOffset = "sni-mid"
	}
	if writeOffset == "" {
		writeOffset = "sni-mid"
	}
	return &CompositeRecordThenWriteSplitStrategy{
		RecordSplitOffset: recordOffset,
		WriteSplitOffset:  writeOffset,
		Delay:             delay,
	}
}

// Name returns the strategy identifier.
func (s *CompositeRecordThenWriteSplitStrategy) Name() string {
	return "tls-record-then-write-split"
}

// Plan executes Stage 1 (TLS record split) and Stage 2 (TCP write split in sequence).
// If any stage fails validation or preconditions, it cleanly falls back to the original unmodified bytes.
func (s *CompositeRecordThenWriteSplitStrategy) Plan(ctx context.Context, input []byte, meta *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	if len(input) == 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       nil,
		}, nil
	}

	// Stage 1: TLS Record Split
	recStrategy := NewTLSRecordSplitStrategy(s.RecordSplitOffset)
	recPlan, err := recStrategy.Plan(ctx, input, meta)
	if err != nil || recPlan.IsFallback || len(recPlan.Chunks) == 0 {
		reason := "stage1_record_split_failed"
		if recPlan.IsFallback {
			reason = recPlan.FallbackReason
		}
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: reason,
		}, nil
	}

	transformedBytes := recPlan.Chunks[0].Data

	// Parse the newly synthesized multi-record buffer so Stage 2 has exact record metadata
	reparseRes := tlsparse.ParseClientHello(transformedBytes, tlsparse.DefaultLimits())
	if reparseRes.Status != tlsparse.StatusParsed || reparseRes.Metadata == nil {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "stage1_output_reparse_failed",
		}, nil
	}

	// Stage 2: TCP Write Split on the transformed records
	writeStrategy := NewTCPWriteSplitStrategy(s.WriteSplitOffset, s.Delay)
	writePlan, err := writeStrategy.Plan(ctx, transformedBytes, reparseRes.Metadata)
	if err != nil || writePlan.IsFallback {
		reason := "stage2_write_split_failed"
		if writePlan.IsFallback && writePlan.FallbackReason != "" {
			reason = writePlan.FallbackReason
		} else if err != nil {
			reason = err.Error()
		}
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: reason,
		}, nil
	}

	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks:       writePlan.Chunks,
		IsFallback:   false,
	}, nil
}

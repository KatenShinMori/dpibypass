package strategy

import (
	"context"
	"time"

	"dpibypass/internal/tlsparse"
)

// TCPWriteSplitStrategy splits initial application bytes across two discrete Go socket writes.
// NOTE: Application-level socket write boundaries do not guarantee distinct TCP segments or
// packet boundaries on the physical wire; operating system networking stacks and middleboxes
// may coalesce or resegment streams.
type TCPWriteSplitStrategy struct {
	Offset string
	Delay  time.Duration
}

// NewTCPWriteSplitStrategy creates a TCPWriteSplitStrategy with configured offset and delay.
func NewTCPWriteSplitStrategy(offset string, delay time.Duration) *TCPWriteSplitStrategy {
	if offset == "" {
		offset = "sni-mid"
	}
	return &TCPWriteSplitStrategy{
		Offset: offset,
		Delay:  delay,
	}
}

// Name returns the strategy identifier.
func (s *TCPWriteSplitStrategy) Name() string {
	return "tcp-write-split"
}

// Plan computes the wire split offset and partitions the input into two WriteChunks.
// If preconditions fail (e.g. SNI missing for sni-* offset), it returns a safe fallback plan.
func (s *TCPWriteSplitStrategy) Plan(_ context.Context, input []byte, meta *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	if len(input) == 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       nil,
		}, nil
	}

	wireOffset, err := ResolveSplitOffset(input, meta, s.Offset)
	if err != nil {
		// Preconditions not satisfied: cleanly fall back to none without corrupting input
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: err.Error(),
		}, nil
	}

	if wireOffset <= 0 || wireOffset >= len(input) {
		return ExecutionPlan{
			StrategyName:   s.Name(),
			Chunks:         []WriteChunk{{Data: input}},
			IsFallback:     true,
			FallbackReason: "resolved_wire_offset_out_of_bounds",
		}, nil
	}

	chunk1 := input[:wireOffset]
	chunk2 := input[wireOffset:]

	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks: []WriteChunk{
			{
				Data:  chunk1,
				Delay: 0,
			},
			{
				Data:  chunk2,
				Delay: s.Delay,
			},
		},
		IsFallback: false,
	}, nil
}

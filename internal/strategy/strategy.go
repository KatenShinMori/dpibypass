package strategy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"dpibypass/internal/tlsparse"
)

// Common errors.
var (
	ErrAbortedPartialWrite  = errors.New("upstream write failed during chunk transmission; connection aborted")
	ErrPreconditionFailed   = errors.New("strategy precondition not met")
	ErrTransformationFailed = errors.New("strategy transformation failed re-validation")
)

// WriteChunk represents a single discrete application socket write.
type WriteChunk struct {
	Data  []byte
	Delay time.Duration
}

// ExecutionPlan specifies the ordered socket writes produced by a strategy.
type ExecutionPlan struct {
	StrategyName   string
	Chunks         []WriteChunk
	IsFallback     bool
	FallbackReason string
}

// TotalBytes returns the sum of bytes across all chunks in the plan.
func (p ExecutionPlan) TotalBytes() int {
	total := 0
	for _, c := range p.Chunks {
		total += len(c.Data)
	}
	return total
}

// Strategy transforms initial application data into an ExecutionPlan.
type Strategy interface {
	Name() string
	Plan(ctx context.Context, input []byte, meta *tlsparse.ClientHelloMetadata) (ExecutionPlan, error)
}

// Execute writes all chunks in the plan to w in order, enforcing partial-write safety and delays.
// CRITICAL INVARIANT: If an error occurs after any bytes have been written, it returns
// ErrAbortedPartialWrite wrapped with the underlying error. The caller MUST abort the connection
// rather than attempting to retransmit or fall back, avoiding stream corruption.
func Execute(ctx context.Context, w io.Writer, plan ExecutionPlan) (int, error) {
	totalWritten := 0

	for i, chunk := range plan.Chunks {
		if ctx.Err() != nil {
			if totalWritten > 0 {
				return totalWritten, fmt.Errorf("%w: %v", ErrAbortedPartialWrite, ctx.Err())
			}
			return 0, ctx.Err()
		}

		// Optional delay before or between chunks
		if chunk.Delay > 0 && i > 0 {
			select {
			case <-time.After(chunk.Delay):
			case <-ctx.Done():
				return totalWritten, fmt.Errorf("%w: %v", ErrAbortedPartialWrite, ctx.Err())
			}
		}

		// Complete socket write loop to guarantee full chunk delivery despite partial writes
		remaining := chunk.Data
		for len(remaining) > 0 {
			n, err := w.Write(remaining)
			totalWritten += n
			if err != nil {
				return totalWritten, fmt.Errorf("%w: chunk %d write: %v", ErrAbortedPartialWrite, i, err)
			}
			if n == 0 {
				return totalWritten, fmt.Errorf("%w: chunk %d zero-byte write", ErrAbortedPartialWrite, i)
			}
			remaining = remaining[n:]
		}
	}

	return totalWritten, nil
}

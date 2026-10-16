package strategy

import (
	"context"
	"time"

	"dpibypass/internal/tlsparse"
)

// Default multi-write parameters.
const (
	DefaultMultiWriteChunkSize = 16
	DefaultMultiWriteMaxChunks = 16
	MaxAllowedChunks           = 32
)

// MultiWriteSplitStrategy writes initial data across multiple bounded chunks.
// It guarantees byte-stream preservation and bounds socket-write overhead.
type MultiWriteSplitStrategy struct {
	ChunkSize int
	MaxChunks int
	Delay     time.Duration
}

// NewMultiWriteSplitStrategy constructs a validated MultiWriteSplitStrategy.
func NewMultiWriteSplitStrategy(chunkSize, maxChunks int, delay time.Duration) *MultiWriteSplitStrategy {
	if chunkSize <= 0 {
		chunkSize = DefaultMultiWriteChunkSize
	}
	if maxChunks <= 0 {
		maxChunks = DefaultMultiWriteMaxChunks
	}
	if maxChunks > MaxAllowedChunks {
		maxChunks = MaxAllowedChunks
	}
	return &MultiWriteSplitStrategy{
		ChunkSize: chunkSize,
		MaxChunks: maxChunks,
		Delay:     delay,
	}
}

// Name returns the strategy identifier.
func (s *MultiWriteSplitStrategy) Name() string {
	return "multi-write-split"
}

// Plan partitions input into up to MaxChunks discrete WriteChunks.
func (s *MultiWriteSplitStrategy) Plan(_ context.Context, input []byte, _ *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	if len(input) == 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       nil,
		}, nil
	}

	chunkSize := s.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultMultiWriteChunkSize
	}
	maxChunks := s.MaxChunks
	if maxChunks <= 0 || maxChunks > MaxAllowedChunks {
		maxChunks = DefaultMultiWriteMaxChunks
	}

	var chunks []WriteChunk
	remaining := input

	for len(remaining) > 0 {
		// If on last allowed chunk slot, put all remaining bytes in this chunk
		if len(chunks) == maxChunks-1 || len(remaining) <= chunkSize {
			chunks = append(chunks, WriteChunk{
				Data:  remaining,
				Delay: s.Delay,
			})
			break
		}

		chunks = append(chunks, WriteChunk{
			Data:  remaining[:chunkSize],
			Delay: s.Delay,
		})
		remaining = remaining[chunkSize:]
	}

	// First chunk has zero delay
	if len(chunks) > 0 {
		chunks[0].Delay = 0
	}

	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks:       chunks,
		IsFallback:   false,
	}, nil
}

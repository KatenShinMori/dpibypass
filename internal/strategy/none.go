package strategy

import (
	"context"

	"dpibypass/internal/tlsparse"
)

// NoneStrategy forwards initial application data in a single socket write without modification.
// This is the baseline, rollback path, and universal fallback strategy.
type NoneStrategy struct{}

// NewNoneStrategy creates an instance of NoneStrategy.
func NewNoneStrategy() *NoneStrategy {
	return &NoneStrategy{}
}

// Name returns the strategy identifier.
func (s *NoneStrategy) Name() string {
	return "none"
}

// Plan wraps the input in a single WriteChunk, preserving the byte stream verbatim.
func (s *NoneStrategy) Plan(_ context.Context, input []byte, _ *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	if len(input) == 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       nil,
		}, nil
	}

	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks: []WriteChunk{
			{
				Data:  input,
				Delay: 0,
			},
		},
		IsFallback: false,
	}, nil
}

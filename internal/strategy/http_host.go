package strategy

import (
	"context"
	"strings"
	"time"

	"dpibypass/internal/tlsparse"
)

// HTTPHostTweakStrategy transforms plain unencrypted HTTP request headers.
// It is STRICTLY prohibited from running on HTTPS / TLS streams.
// Valid variations include case variation (e.g. "host:" instead of "Host:"),
// spacing variation, and socket write-splitting of the Host header line.
type HTTPHostTweakStrategy struct {
	Variation string        // "lowercase", "space", or "split"
	Delay     time.Duration // delay between split writes if variation is "split"
}

// NewHTTPHostTweakStrategy constructs an HTTPHostTweakStrategy.
func NewHTTPHostTweakStrategy(variation string, delay time.Duration) *HTTPHostTweakStrategy {
	norm := strings.ToLower(strings.TrimSpace(variation))
	if norm == "" {
		norm = "lowercase"
	}
	return &HTTPHostTweakStrategy{
		Variation: norm,
		Delay:     delay,
	}
}

// Name returns the strategy identifier.
func (s *HTTPHostTweakStrategy) Name() string {
	return "http-host-tweak"
}

// Plan satisfies the Strategy interface for consistency.
func (s *HTTPHostTweakStrategy) Plan(_ context.Context, input []byte, _ *tlsparse.ClientHelloMetadata) (ExecutionPlan, error) {
	// For raw byte streams, transform plain HTTP headers
	transformed, chunks := s.TransformHeaders(string(input))
	if len(chunks) > 0 {
		return ExecutionPlan{
			StrategyName: s.Name(),
			Chunks:       chunks,
			IsFallback:   false,
		}, nil
	}
	return ExecutionPlan{
		StrategyName: s.Name(),
		Chunks: []WriteChunk{
			{
				Data:  []byte(transformed),
				Delay: 0,
			},
		},
		IsFallback: false,
	}, nil
}

// TransformHeaders applies the configured variation to plain HTTP request header text.
func (s *HTTPHostTweakStrategy) TransformHeaders(headers string) (string, []WriteChunk) {
	lines := strings.Split(headers, "\r\n")
	foundHost := false
	hostLineIndex := -1

	for idx, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			foundHost = true
			hostLineIndex = idx
			break
		}
	}

	if !foundHost || hostLineIndex == -1 {
		// No host header found: preserve unchanged
		return headers, nil
	}

	origHostLine := lines[hostLineIndex]
	colonIdx := strings.Index(origHostLine, ":")
	if colonIdx == -1 {
		return headers, nil
	}

	switch s.Variation {
	case "space":
		// Host: <space><space>domain
		headerVal := strings.TrimLeft(origHostLine[colonIdx+1:], " \t")
		lines[hostLineIndex] = "Host:  " + headerVal
		res := strings.Join(lines, "\r\n")
		return res, nil

	case "split":
		// Split socket write across the middle of Host header
		val := strings.TrimSpace(origHostLine[colonIdx+1:])
		if len(val) >= 2 {
			mid := len(val) / 2
			part1Val := val[:mid]
			part2Val := val[mid:]

			lines[hostLineIndex] = "Host: " + part1Val
			prefix := strings.Join(lines[:hostLineIndex+1], "\r\n")

			suffix := part2Val + "\r\n" + strings.Join(lines[hostLineIndex+1:], "\r\n")
			return headers, []WriteChunk{
				{Data: []byte(prefix), Delay: 0},
				{Data: []byte(suffix), Delay: s.Delay},
			}
		}
		// If value too short to split, fall through to lowercase
		fallthrough

	case "lowercase":
		fallthrough
	default:
		// "host: domain" instead of "Host: domain" per RFC 7230/9110
		headerVal := origHostLine[colonIdx+1:]
		lines[hostLineIndex] = "host:" + headerVal
		res := strings.Join(lines, "\r\n")
		return res, nil
	}
}

package strategy

import (
	"fmt"
	"strings"
	"time"

	"dpibypass/internal/config"
)

// FromProfile builds a Strategy instance from a config.ProfileConfig.
// It maps the configuration type and parameters deterministically.
func FromProfile(p config.ProfileConfig) (Strategy, error) {
	normType := strings.ToLower(strings.TrimSpace(p.Type))
	if normType == "" {
		normType = "none"
	}

	delay := time.Duration(p.DelayMS) * time.Millisecond

	switch normType {
	case "none", "packet":
		return NewNoneStrategy(), nil

	case "tcp-write-split":
		offset := p.Offset
		if offset == "" {
			offset = "sni-mid"
		}
		return NewTCPWriteSplitStrategy(offset, delay), nil

	case "multi-write-split":
		chunkSize := p.ChunkSize
		if chunkSize <= 0 {
			chunkSize = DefaultMultiWriteChunkSize
		}
		maxChunks := p.MaxChunks
		if maxChunks <= 0 {
			maxChunks = DefaultMultiWriteMaxChunks
		}
		return NewMultiWriteSplitStrategy(chunkSize, maxChunks, delay), nil

	case "tls-record-split":
		offset := p.Offset
		if offset == "" {
			offset = "sni-mid"
		}
		return NewTLSRecordSplitStrategy(offset), nil

	case "tls-record-then-write-split":
		// Precedence: specific record_offset and write_offset take precedence over legacy offset.
		// If either is omitted, it falls back to legacy offset; if legacy offset is omitted,
		// it defaults to "sni-mid".
		recordOffset := strings.TrimSpace(p.RecordOffset)
		if recordOffset == "" {
			recordOffset = strings.TrimSpace(p.Offset)
		}
		if recordOffset == "" {
			recordOffset = "sni-mid"
		}

		writeOffset := strings.TrimSpace(p.WriteOffset)
		if writeOffset == "" {
			writeOffset = strings.TrimSpace(p.Offset)
		}
		if writeOffset == "" {
			writeOffset = "sni-mid"
		}
		return NewCompositeRecordThenWriteSplitStrategy(recordOffset, writeOffset, delay), nil

	case "http-host-tweak":
		variation := p.HostHeaderTweak
		if variation == "" {
			variation = "lowercase"
		}
		return NewHTTPHostTweakStrategy(variation, delay), nil

	default:
		return nil, fmt.Errorf("unknown strategy type %q", p.Type)
	}
}

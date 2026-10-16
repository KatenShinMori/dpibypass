package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/strategy"
)

// ExecuteStrategyAndRelay coordinates the Phase 1 strategy execution lifecycle:
//  1. Accumulates initial client data (up to MaxInitialBytes, InitialInspectionTimeout, or complete ClientHello).
//  2. Selects and plans the configured strategy for the target.
//  3. Writes the planned chunks to the upstream socket.
//  4. If an upstream write error occurs during chunk delivery, aborts the connection immediately
//     without retransmission.
//  5. Enters BidirectionalRelay for all subsequent traffic without modification.
func ExecuteStrategyAndRelay(
	ctx context.Context,
	clientConn net.Conn,
	upstreamConn net.Conn,
	preBuffered []byte,
	targetHost string,
	logger *slog.Logger,
	cfg HandlerConfig,
) error {
	// 1. Accumulate initial client application data
	initialData, parseRes, err := AccumulateInitialData(
		ctx,
		clientConn,
		preBuffered,
		cfg.InitialInspectionTimeout,
		cfg.MaxInitialBytes,
	)
	if err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return fmt.Errorf("accumulate initial client data: %w", err)
	}

	// 2. If client hasn't sent any data, enter relay directly
	if len(initialData) == 0 {
		return BidirectionalRelay(ctx, clientConn, upstreamConn, nil, RelayConfig{
			IdleTimeout: cfg.IdleTimeout,
		})
	}

	// 3. Resolve strategy profile via domain matching rules
	var selectedProfileName string
	var matchedRule bool
	var matchSource string

	// 1. If valid TLS SNI hostname is available and a rule matches it, use that rule
	if parseRes.Metadata != nil && parseRes.Metadata.HasSNI && parseRes.Metadata.SNI != "" {
		if cfg.Matcher != nil {
			if profName, ok := cfg.Matcher.Match(parseRes.Metadata.SNI); ok {
				selectedProfileName = profName
				matchedRule = true
				matchSource = "sni"
			}
		}
	}

	// 2. Otherwise, try the proxy target hostname when it is a DNS hostname (not an IP literal)
	if !matchedRule && targetHost != "" && net.ParseIP(targetHost) == nil {
		if cfg.Matcher != nil {
			if profName, ok := cfg.Matcher.Match(targetHost); ok {
				selectedProfileName = profName
				matchedRule = true
				matchSource = "target_host"
			}
		}
	}

	var prof config.ProfileConfig
	if matchedRule {
		p, ok := cfg.Profiles[selectedProfileName]
		if !ok {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
			return fmt.Errorf("matched domain rule (%s) references undefined profile %q", matchSource, selectedProfileName)
		}
		prof = p
	} else {
		prof = cfg.DefaultProfile
	}

	if prof.Type == "" {
		prof = config.ProfileConfig{Type: "none"}
	}

	strat, err := strategy.FromProfile(prof)
	if err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return fmt.Errorf("build strategy for profile: %w", err)
	}

	// 4. Plan strategy
	plan, err := strat.Plan(ctx, initialData, parseRes.Metadata)
	if err != nil {
		// Clean fallback to none on any planning error
		fallbackStrat := strategy.NewNoneStrategy()
		plan, _ = fallbackStrat.Plan(ctx, initialData, parseRes.Metadata)
		plan.IsFallback = true
		plan.FallbackReason = err.Error()
	}

	// 5. Execute plan upstream
	if cfg.IdleTimeout > 0 {
		_ = upstreamConn.SetWriteDeadline(time.Now().Add(cfg.IdleTimeout))
	}

	written, writeErr := strategy.Execute(ctx, upstreamConn, plan)
	_ = upstreamConn.SetWriteDeadline(time.Time{}) // Clear write deadline

	if writeErr != nil {
		// Transmission failed: abort immediately; do not retransmit to avoid corrupting stream
		logger.Warn("upstream write failed during strategy chunk transmission; aborting connection",
			TargetLogAttr(targetHost),
			slog.String("strategy", plan.StrategyName),
			slog.Int("bytes_written", written),
			slog.String("error_category", ClassifyError(writeErr)),
		)
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return fmt.Errorf("strategy write upstream: %w", writeErr)
	}

	logger.Debug("initial data strategy applied",
		TargetLogAttr(targetHost),
		slog.String("strategy", plan.StrategyName),
		slog.Bool("fallback", plan.IsFallback),
		slog.String("fallback_reason", plan.FallbackReason),
		slog.Int("chunks", len(plan.Chunks)),
		slog.Int("total_bytes", written),
	)

	// 6. Enter Bidirectional Relay with initialBuffered=nil (initial bytes already delivered)
	return BidirectionalRelay(ctx, clientConn, upstreamConn, nil, RelayConfig{
		IdleTimeout: cfg.IdleTimeout,
	})
}

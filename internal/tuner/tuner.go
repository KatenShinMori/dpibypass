package tuner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/diagnostics"
	"dpibypass/internal/strategy"
)

const (
	DefaultTrials     = 3
	DefaultInterDelay = 500 * time.Millisecond
	MaxTrials         = 10
	MaxInterDelay     = 10 * time.Second
)

// CheckFunc defines the connectivity check execution function signature.
type CheckFunc func(ctx context.Context, domain string, port int, strat strategy.Strategy, cfg diagnostics.CheckerConfig) diagnostics.CheckResult

// TunerConfig configures the evaluation parameters for strategy tuning.
type TunerConfig struct {
	Trials        int
	InterDelay    time.Duration
	Port          int
	CheckerConfig diagnostics.CheckerConfig
	Profiles      map[string]config.ProfileConfig
	CheckFunc     CheckFunc // Optional injected checker for deterministic testing (nil uses diagnostics.RunCheck)
}

// DefaultTunerConfig returns safe default parameters for multi-trial evaluation.
func DefaultTunerConfig() TunerConfig {
	return TunerConfig{
		Trials:        DefaultTrials,
		InterDelay:    DefaultInterDelay,
		Port:          diagnostics.DefaultPort,
		CheckerConfig: diagnostics.DefaultCheckerConfig(),
		Profiles:      make(map[string]config.ProfileConfig),
	}
}

// TuneDomain evaluates baseline 'none' and candidate profiles sequentially against domain.
func TuneDomain(
	ctx context.Context,
	domain string,
	candidateProfileNames []string,
	cfg TunerConfig,
) DomainTuneResult {
	if cfg.Trials <= 0 {
		cfg.Trials = DefaultTrials
	}
	if cfg.Trials > MaxTrials {
		cfg.Trials = MaxTrials
	}
	if cfg.InterDelay < 0 {
		cfg.InterDelay = DefaultInterDelay
	}
	if cfg.InterDelay > MaxInterDelay {
		cfg.InterDelay = MaxInterDelay
	}
	if cfg.Port <= 0 {
		cfg.Port = diagnostics.DefaultPort
	}

	result := DomainTuneResult{
		Domain: domain,
		Port:   cfg.Port,
	}

	// 1. Evaluate Baseline 'none'
	noneStrat := strategy.NewNoneStrategy()
	result.BaselineStats = runTrials(ctx, domain, cfg.Port, "none", "none", noneStrat, cfg.Trials, cfg.InterDelay, cfg.CheckerConfig, cfg.CheckFunc)

	// Determine candidate profile list
	var profilesToTest []string
	if len(candidateProfileNames) > 0 {
		for _, name := range candidateProfileNames {
			if name != "none" {
				profilesToTest = append(profilesToTest, name)
			}
		}
	} else {
		for name := range cfg.Profiles {
			if name != "none" {
				profilesToTest = append(profilesToTest, name)
			}
		}
		sort.Strings(profilesToTest)
	}

	// 2. Evaluate Candidate Profiles
	for _, profName := range profilesToTest {
		profCfg, exists := cfg.Profiles[profName]
		if !exists {
			result.CandidateStats = append(result.CandidateStats, ProfileStats{
				ProfileName:       profName,
				StrategyType:      "unknown",
				Unsupported:       true,
				UnsupportedReason: fmt.Sprintf("profile %q not declared in configuration", profName),
			})
			continue
		}

		strat, err := strategy.FromProfile(profCfg)
		if err != nil {
			result.CandidateStats = append(result.CandidateStats, ProfileStats{
				ProfileName:       profName,
				StrategyType:      profCfg.Type,
				Unsupported:       true,
				UnsupportedReason: err.Error(),
			})
			continue
		}

		stats := runTrials(ctx, domain, cfg.Port, profName, profCfg.Type, strat, cfg.Trials, cfg.InterDelay, cfg.CheckerConfig, cfg.CheckFunc)
		result.CandidateStats = append(result.CandidateStats, stats)
	}

	// 3. Formulate Recommendation
	evaluateRecommendation(&result, cfg.Trials)

	return result
}

func runTrials(
	ctx context.Context,
	domain string,
	port int,
	profName string,
	stratType string,
	strat strategy.Strategy,
	trials int,
	delay time.Duration,
	chkCfg diagnostics.CheckerConfig,
	checkFn CheckFunc,
) ProfileStats {
	stats := ProfileStats{
		ProfileName:    profName,
		StrategyType:   stratType,
		Trials:         trials,
		FailureClasses: make(map[diagnostics.Outcome]int),
	}

	var latencies []time.Duration
	outcomeCounts := make(map[diagnostics.Outcome]int)

	fn := checkFn
	if fn == nil {
		fn = diagnostics.RunCheck
	}

	for t := 0; t < trials; t++ {
		if t > 0 && delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return stats
			}
		}

		res := fn(ctx, domain, port, strat, chkCfg)

		outcomeCounts[res.Outcome]++
		if res.IsSuccess() {
			stats.Successes++
			latencies = append(latencies, res.TotalDuration)
		} else {
			stats.Failures++
			stats.FailureClasses[res.Outcome]++
		}

		if res.Outcome == diagnostics.OutcomeUnsupportedStrategy {
			stats.Unsupported = true
			stats.UnsupportedReason = res.FailureReason
		}
	}

	// Determine dominant outcome
	maxCount := -1
	for outcome, count := range outcomeCounts {
		if count > maxCount {
			maxCount = count
			stats.DominantOutcome = outcome
		}
	}

	// Compute latency statistics
	if len(latencies) > 0 {
		var sum time.Duration
		stats.MinLatency = latencies[0]
		stats.MaxLatency = latencies[0]
		for _, lat := range latencies {
			sum += lat
			if lat < stats.MinLatency {
				stats.MinLatency = lat
			}
			if lat > stats.MaxLatency {
				stats.MaxLatency = lat
			}
		}
		stats.AvgLatency = sum / time.Duration(len(latencies))
	}

	return stats
}

func evaluateRecommendation(r *DomainTuneResult, totalTrials int) {
	// Rule 1: If baseline works consistently (all trials pass), retain baseline 'none'
	if r.BaselineStats.Successes == totalTrials {
		r.RecommendedProfile = "none"
		r.RecommendationReason = "Baseline 'none' succeeded consistently across all trials; bypass strategy unnecessary."
		r.IsConclusive = true
		return
	}

	// Rule 2: If baseline had intermittent success (not 0, but < totalTrials), inconclusive
	if r.BaselineStats.Successes > 0 && r.BaselineStats.Successes < totalTrials {
		r.RecommendedProfile = ""
		r.RecommendationReason = fmt.Sprintf("Inconclusive: Baseline 'none' exhibited intermittent behavior (%d/%d successes); evidence is insufficient to justify changing profile.", r.BaselineStats.Successes, totalTrials)
		r.IsConclusive = false
		return
	}

	// Rule 3: Baseline failed completely (0 successes). Check for candidates with 100% success.
	var bestCandidate *ProfileStats
	for i := range r.CandidateStats {
		c := &r.CandidateStats[i]
		if c.Unsupported {
			continue
		}
		if c.Successes == totalTrials {
			if bestCandidate == nil || c.AvgLatency < bestCandidate.AvgLatency {
				bestCandidate = c
			}
		}
	}

	if bestCandidate != nil {
		r.RecommendedProfile = bestCandidate.ProfileName
		r.RecommendationReason = fmt.Sprintf("Candidate %q demonstrated consistent improvement (%d/%d successes) over failing baseline (%d/%d successes).",
			bestCandidate.ProfileName, bestCandidate.Successes, totalTrials, r.BaselineStats.Successes, totalTrials)
		r.IsConclusive = true
		return
	}

	// Rule 4: If no candidate succeeded consistently
	r.RecommendedProfile = ""
	r.RecommendationReason = "Inconclusive: Neither baseline nor candidate profiles achieved repeatable success across all trials."
	r.IsConclusive = false
}

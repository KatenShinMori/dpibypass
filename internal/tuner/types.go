package tuner

import (
	"time"

	"dpibypass/internal/diagnostics"
)

// ProfileStats tracks aggregated metrics across multi-trial probes for a single profile.
type ProfileStats struct {
	ProfileName       string
	StrategyType      string
	Trials            int
	Successes         int
	Failures          int
	FailureClasses    map[diagnostics.Outcome]int
	MinLatency        time.Duration
	AvgLatency        time.Duration
	MaxLatency        time.Duration
	DominantOutcome   diagnostics.Outcome
	Unsupported       bool
	UnsupportedReason string
}

// DomainTuneResult contains the evaluation results and recommendation for a single domain.
type DomainTuneResult struct {
	Domain               string
	Port                 int
	BaselineStats        ProfileStats
	CandidateStats       []ProfileStats
	RecommendedProfile   string
	RecommendationReason string
	IsConclusive         bool
}

package tuner

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

// FormatReport renders a structured ASCII report table for one or more tuned domains.
func FormatReport(results []DomainTuneResult) string {
	var buf bytes.Buffer

	for i, res := range results {
		if i > 0 {
			buf.WriteString("\n" + strings.Repeat("-", 78) + "\n\n")
		}

		buf.WriteString(fmt.Sprintf("Tuning Report for Target: %s:%d\n\n", res.Domain, res.Port))

		tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROFILE\tTYPE\tTRIALS\tSUCCESS\tFAIL\tDOMINANT OUTCOME\tAVG LATENCY")
		fmt.Fprintln(tw, "-------\t----\t------\t-------\t----\t----------------\t-----------")

		// Print Baseline
		printProfileRow(tw, res.BaselineStats)

		// Print Candidates
		for _, cand := range res.CandidateStats {
			printProfileRow(tw, cand)
		}

		_ = tw.Flush()

		buf.WriteString("\nEvaluation Summary:\n")
		if res.IsConclusive {
			buf.WriteString(fmt.Sprintf("  Recommendation : %s\n", res.RecommendedProfile))
		} else {
			buf.WriteString("  Recommendation : INCONCLUSIVE (no change recommended)\n")
		}
		buf.WriteString(fmt.Sprintf("  Rationale      : %s\n", res.RecommendationReason))
		buf.WriteString("\nNote: Diagnostics measure observed connectivity and protocol outcomes;\n")
		buf.WriteString("      they do not independently establish DPI interference or guarantee\n")
		buf.WriteString("      that a strategy will bypass a real ISP's DPI.\n")
	}

	return buf.String()
}

func printProfileRow(tw *tabwriter.Writer, s ProfileStats) {
	if s.Unsupported {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\tUNSUPPORTED (%s)\t-\n",
			s.ProfileName, s.StrategyType, s.Trials, s.Successes, s.Failures, s.UnsupportedReason)
		return
	}

	avgLat := "-"
	if s.Successes > 0 && s.AvgLatency > 0 {
		avgLat = formatDuration(s.AvgLatency)
	}

	outcomeStr := s.DominantOutcome.String()
	if s.Failures > 0 {
		var failDetails []string
		for outcome, count := range s.FailureClasses {
			if count > 0 {
				failDetails = append(failDetails, fmt.Sprintf("%s:%d", outcome.String(), count))
			}
		}
		if len(failDetails) > 0 {
			outcomeStr = fmt.Sprintf("%s (%s)", outcomeStr, strings.Join(failDetails, ","))
		}
	}

	fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%s\t%s\n",
		s.ProfileName, s.StrategyType, s.Trials, s.Successes, s.Failures, outcomeStr, avgLat)
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

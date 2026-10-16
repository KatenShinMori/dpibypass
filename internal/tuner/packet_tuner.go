package tuner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/dnsdoh"
)

// DefaultCandidateTTLs are the standard hop counts evaluated during auto-TTL calibration.
var DefaultCandidateTTLs = []uint8{3, 4, 5, 6, 7}

// DNSCheckResult records the comparison between Windows System DNS and DoH.
type DNSCheckResult struct {
	Domain        string
	SystemIPs     []net.IP
	DoHIPs        []net.IP
	SystemError   error
	DoHError      error
	PoisoningRisk bool
	Warning       string
}

// TTLProbeStats records multi-trial results for a specific fake_ttl value.
type TTLProbeStats struct {
	TTL        uint8
	Trials     int
	Successes  int
	Failures   int
	AvgLatency time.Duration
}

// PacketTuneResult contains the evaluation results and minimum working TTL recommendation for a domain.
type PacketTuneResult struct {
	Domain               string
	Port                 int
	DNSCheck             DNSCheckResult
	CandidateStats       []TTLProbeStats
	RecommendedTTL       uint8
	RecommendationReason string
	IsConclusive         bool
}

// PacketProbeFunc defines the probe function signature for testing a given TTL value.
type PacketProbeFunc func(ctx context.Context, domain string, port int, ttl uint8) (bool, time.Duration, error)

// ResolverLookupIP abstracts IP address resolution for both system DNS and DoH.
type ResolverLookupIP interface {
	LookupIP(ctx context.Context, domain string) ([]net.IP, error)
}

// TLSVerifierFunc abstracts verifying a TLS certificate against an IP address.
type TLSVerifierFunc func(ctx context.Context, ip net.IP, port int, domain string) error

func defaultTLSVerifier(ctx context.Context, ip net.IP, port int, domain string) error {
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	tlsConfig := &tls.Config{
		ServerName: domain,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// isKnownISPSinkholeIP returns true if ip matches well-known national ISP DNS sinkhole/block ranges.
// Specifically includes Türk Telekom (TTNet AS9121) 195.175.0.0/16 (e.g. 195.175.254.2 block page).
func isKnownISPSinkholeIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 195 && ip4[1] == 175 {
			return true
		}
	}
	return false
}

// CheckDNSPoisoning verifies whether system DNS resolves domain cleanly compared to secure DoH.
// If dohResolver is nil, a default DoH resolver using Cloudflare/Google is initialized.
func CheckDNSPoisoning(ctx context.Context, domain string, dohResolver ResolverLookupIP) DNSCheckResult {
	return CheckDNSPoisoningWithResolvers(ctx, domain, nil, dohResolver, defaultTLSVerifier)
}

// CheckDNSPoisoningWithResolvers allows injecting custom/mock system and DoH resolvers as well as TLS verifiers.
func CheckDNSPoisoningWithResolvers(
	ctx context.Context,
	domain string,
	sysResolver ResolverLookupIP,
	dohResolver ResolverLookupIP,
	tlsVerifier TLSVerifierFunc,
) DNSCheckResult {
	res := DNSCheckResult{Domain: domain}

	// 1. Resolve via System DNS (or injected sysResolver)
	if sysResolver != nil {
		sysIPs, sysErr := sysResolver.LookupIP(ctx, domain)
		if sysErr != nil {
			res.SystemError = sysErr
		} else {
			res.SystemIPs = sysIPs
		}
	} else {
		sysIPAddrs, sysErr := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if sysErr != nil {
			res.SystemError = sysErr
		} else {
			for _, ipa := range sysIPAddrs {
				res.SystemIPs = append(res.SystemIPs, ipa.IP)
			}
		}
	}

	// 2. Resolve via DoH
	if dohResolver == nil {
		dohCfg := config.DefaultConfig().DoH
		dohCfg.Enabled = true
		nullLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
		defaultDoH, err := dnsdoh.NewResolver(dohCfg, nullLogger)
		if err == nil {
			dohResolver = defaultDoH
		}
	}

	if dohResolver != nil {
		dohIPs, dohErr := dohResolver.LookupIP(ctx, domain)
		if dohErr != nil {
			res.DoHError = dohErr
		} else {
			res.DoHIPs = dohIPs
		}
	}

	// 3. Compare resolutions and evaluate poisoning / sinkhole risk
	if res.SystemError != nil && len(res.DoHIPs) > 0 {
		res.PoisoningRisk = true
		res.Warning = fmt.Sprintf("ISP DNS Poisoning/Failure: System DNS failed (%v), but DoH resolved to %v", res.SystemError, res.DoHIPs)
		return res
	}

	for _, ip := range res.SystemIPs {
		if ip.IsLoopback() || ip.IsUnspecified() {
			res.PoisoningRisk = true
			res.Warning = fmt.Sprintf("ISP DNS Sinkhole detected: System DNS returned sinkhole IP %s for %s", ip.String(), domain)
			return res
		}
		if isPrivateOrBogonIP(ip) && !anyPrivateOrBogon(res.DoHIPs) {
			res.PoisoningRisk = true
			res.Warning = fmt.Sprintf("ISP DNS Manipulation detected: System DNS returned private/bogon IP %s for %s", ip.String(), domain)
			return res
		}
		if isKnownISPSinkholeIP(ip) {
			res.PoisoningRisk = true
			res.Warning = fmt.Sprintf("ISP DNS Sinkhole detected: System DNS returned known ISP sinkhole/block page IP %s for %s", ip.String(), domain)
			return res
		}
	}

	// 4. Divergence Check between Public System IPs and DoH IPs
	if len(res.SystemIPs) > 0 && len(res.DoHIPs) > 0 {
		hasOverlap := false
		for _, sIP := range res.SystemIPs {
			for _, dIP := range res.DoHIPs {
				if sIP.Equal(dIP) {
					hasOverlap = true
					break
				}
			}
			if hasOverlap {
				break
			}
		}

		if !hasOverlap && tlsVerifier != nil {
			targetIP := res.SystemIPs[0]
			if certErr := tlsVerifier(ctx, targetIP, 443, domain); certErr != nil {
				res.PoisoningRisk = true
				res.Warning = fmt.Sprintf("ISP DNS Hijacking detected: System DNS returned IP %s which failed TLS certificate verification (%v) for %s while DoH returned %v", targetIP.String(), certErr, domain, res.DoHIPs)
				return res
			}
		}
	}

	return res
}

func isPrivateOrBogonIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31) {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 (Carrier-Grade NAT)
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return true
		}
	}
	return false
}

func anyPrivateOrBogon(ips []net.IP) bool {
	for _, ip := range ips {
		if isPrivateOrBogonIP(ip) {
			return true
		}
	}
	return false
}

// TunePacketDomain sweeps candidate TTL values and selects the minimum working TTL
// that achieves 100% success across all trials.
func TunePacketDomain(
	ctx context.Context,
	domain string,
	port int,
	candidateTTLs []uint8,
	trials int,
	interDelay time.Duration,
	dnsCheck DNSCheckResult,
	probeFn PacketProbeFunc,
) PacketTuneResult {
	if port <= 0 {
		port = 443
	}
	if trials <= 0 {
		trials = DefaultTrials
	}
	if trials > MaxTrials {
		trials = MaxTrials
	}
	if len(candidateTTLs) == 0 {
		candidateTTLs = append([]uint8(nil), DefaultCandidateTTLs...)
	}

	// Sort candidate TTLs in ascending order
	ttls := append([]uint8(nil), candidateTTLs...)
	sort.Slice(ttls, func(i, j int) bool {
		return ttls[i] < ttls[j]
	})

	result := PacketTuneResult{
		Domain:   domain,
		Port:     port,
		DNSCheck: dnsCheck,
	}

	if probeFn == nil {
		result.RecommendationReason = "no probe function provided"
		return result
	}

	for _, ttl := range ttls {
		stats := TTLProbeStats{
			TTL:    ttl,
			Trials: trials,
		}

		var totalLatency time.Duration
		for t := 0; t < trials; t++ {
			if t > 0 && interDelay > 0 {
				select {
				case <-time.After(interDelay):
				case <-ctx.Done():
					result.RecommendationReason = "tuning cancelled by context"
					return result
				}
			}

			success, latency, _ := probeFn(ctx, domain, port, ttl)
			if success {
				stats.Successes++
				totalLatency += latency
			} else {
				stats.Failures++
			}
		}

		if stats.Successes > 0 {
			stats.AvgLatency = totalLatency / time.Duration(stats.Successes)
		}
		result.CandidateStats = append(result.CandidateStats, stats)
	}

	evaluateTTLRecommendation(&result, trials)
	return result
}

func evaluateTTLRecommendation(r *PacketTuneResult, totalTrials int) {
	// Select the minimum working TTL (candidate with Successes == totalTrials)
	// Because CandidateStats is sorted in ascending order of TTL, the first match is the minimum.
	for _, c := range r.CandidateStats {
		if c.Successes == totalTrials {
			r.RecommendedTTL = c.TTL
			r.IsConclusive = true
			r.RecommendationReason = fmt.Sprintf("TTL %d is the minimum working hop count achieving 100%% bypass (%d/%d trials).", c.TTL, c.Successes, totalTrials)
			return
		}
	}

	r.RecommendedTTL = 0
	r.IsConclusive = false
	r.RecommendationReason = fmt.Sprintf("Inconclusive: No candidate TTL achieved 100%% bypass across all %d trials.", totalTrials)
}

// FormatPacketReport formats a slice of PacketTuneResult into a clear human-readable string.
func FormatPacketReport(results []PacketTuneResult) string {
	var b strings.Builder
	b.WriteString("=== Packet Mode Strategy Tuning Report (WinDivert Auto-TTL) ===\n\n")

	for _, res := range results {
		b.WriteString(fmt.Sprintf("Target Domain: %s (port %d)\n", res.Domain, res.Port))

		if res.DNSCheck.PoisoningRisk {
			b.WriteString(fmt.Sprintf("  [WARNING] %s\n", res.DNSCheck.Warning))
		} else if len(res.DNSCheck.SystemIPs) > 0 {
			var ips []string
			for _, ip := range res.DNSCheck.SystemIPs {
				ips = append(ips, ip.String())
			}
			b.WriteString(fmt.Sprintf("  DNS Status : Clean (resolved to %s)\n", strings.Join(ips, ", ")))
		}

		b.WriteString("  TTL Sweep:\n")
		b.WriteString("    TTL   Trials   Success   Failure   Avg Latency   Result\n")
		b.WriteString("    ---   ------   -------   -------   -----------   ------\n")

		for _, s := range res.CandidateStats {
			statusStr := "FAIL"
			if s.Successes == s.Trials {
				if s.TTL == res.RecommendedTTL {
					statusStr = "PASS (Optimal Min-TTL)"
				} else {
					statusStr = "PASS"
				}
			} else if s.Successes > 0 {
				statusStr = fmt.Sprintf("INTERMITTENT (%d/%d)", s.Successes, s.Trials)
			}

			latStr := "-"
			if s.Successes > 0 {
				latStr = fmt.Sprintf("%v", s.AvgLatency.Round(time.Millisecond))
			}

			b.WriteString(fmt.Sprintf("    %-5d %-8d %-9d %-9d %-13s %s\n",
				s.TTL, s.Trials, s.Successes, s.Failures, latStr, statusStr))
		}

		b.WriteString(fmt.Sprintf("  Recommendation : "))
		if res.IsConclusive {
			b.WriteString(fmt.Sprintf("fake_ttl = %d\n", res.RecommendedTTL))
		} else {
			b.WriteString("Inconclusive\n")
		}
		b.WriteString(fmt.Sprintf("  Rationale      : %s\n\n", res.RecommendationReason))
	}

	return b.String()
}

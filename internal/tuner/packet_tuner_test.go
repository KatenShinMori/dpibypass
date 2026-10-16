package tuner

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type mockDoHResolver struct {
	ips []net.IP
	err error
}

func (m *mockDoHResolver) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ips, nil
}

func TestCheckDNSPoisoning(t *testing.T) {
	ctx := context.Background()

	t.Run("Clean resolution without poisoning (matching IPs)", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("162.159.130.233")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("162.159.130.233")},
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "updates.discord.com", mockSys, mockDoH, nil)
		if res.PoisoningRisk {
			t.Fatalf("expected PoisoningRisk = false, got true: %s", res.Warning)
		}
	})

	t.Run("ISP sinkhole loopback detection", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("127.0.0.1")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("104.16.12.34")},
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "blocked.example.com", mockSys, mockDoH, nil)
		if !res.PoisoningRisk {
			t.Fatal("expected PoisoningRisk = true for loopback sinkhole")
		}
		if !strings.Contains(res.Warning, "Sinkhole") {
			t.Fatalf("expected warning to mention Sinkhole, got: %s", res.Warning)
		}
	})

	t.Run("ISP private bogon IP detection", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("10.10.10.10")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("104.16.12.34")},
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "blocked.example.com", mockSys, mockDoH, nil)
		if !res.PoisoningRisk {
			t.Fatal("expected PoisoningRisk = true for private bogon IP")
		}
		if !strings.Contains(res.Warning, "Manipulation") {
			t.Fatalf("expected warning to mention Manipulation, got: %s", res.Warning)
		}
	})

	t.Run("ISP known sinkhole IP (Türk Telekom 195.175.254.2)", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("195.175.254.2")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("162.159.130.233")},
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "updates.discord.com", mockSys, mockDoH, nil)
		if !res.PoisoningRisk {
			t.Fatal("expected PoisoningRisk = true for Türk Telekom sinkhole IP 195.175.254.2")
		}
		if !strings.Contains(res.Warning, "195.175.254.2") {
			t.Fatalf("expected warning to mention 195.175.254.2, got: %s", res.Warning)
		}
	})

	t.Run("ISP system failure with DoH success", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			err: errors.New("timeout or NXDOMAIN"),
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("128.116.44.3")},
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "www.roblox.com", mockSys, mockDoH, nil)
		if !res.PoisoningRisk {
			t.Fatal("expected PoisoningRisk = true when system fails but DoH succeeds")
		}
		if !strings.Contains(res.Warning, "Poisoning/Failure") {
			t.Fatalf("expected warning to mention Poisoning/Failure, got: %s", res.Warning)
		}
	})

	t.Run("Divergent IP with invalid TLS certificate", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("1.2.3.4")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("104.16.12.34")},
		}
		mockVerifier := func(ctx context.Context, ip net.IP, port int, domain string) error {
			return errors.New("x509: certificate signed by unknown authority")
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "example.com", mockSys, mockDoH, mockVerifier)
		if !res.PoisoningRisk {
			t.Fatal("expected PoisoningRisk = true when divergent IP fails TLS verification")
		}
		if !strings.Contains(res.Warning, "Hijacking") {
			t.Fatalf("expected warning to mention Hijacking, got: %s", res.Warning)
		}
	})

	t.Run("Divergent IP with valid TLS certificate (legitimate CDN)", func(t *testing.T) {
		mockSys := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("1.2.3.4")},
		}
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("104.16.12.34")},
		}
		mockVerifier := func(ctx context.Context, ip net.IP, port int, domain string) error {
			return nil
		}
		res := CheckDNSPoisoningWithResolvers(ctx, "example.com", mockSys, mockDoH, mockVerifier)
		if res.PoisoningRisk {
			t.Fatalf("expected PoisoningRisk = false for valid CDN edge, got true: %s", res.Warning)
		}
	})

	t.Run("Live fallback with default system resolver", func(t *testing.T) {
		mockDoH := &mockDoHResolver{
			ips: []net.IP{net.ParseIP("127.0.0.1")},
		}
		res := CheckDNSPoisoning(ctx, "localhost", mockDoH)
		if len(res.SystemIPs) == 0 && res.SystemError == nil {
			t.Log("localhost resolved via DefaultResolver")
		}
	})
}

func TestTunePacketDomain_MinimumWorkingTTLSelection(t *testing.T) {
	ctx := context.Background()

	// Scenario:
	// TTL 3: 0/3 (fails)
	// TTL 4: 2/3 (intermittent)
	// TTL 5: 3/3 (100% pass)
	// TTL 6: 3/3 (100% pass)
	// TTL 7: 3/3 (100% pass)
	// Expected selection: TTL 5 (minimum working TTL)

	trialCounts := make(map[uint8]int)
	probeMock := func(ctx context.Context, domain string, port int, ttl uint8) (bool, time.Duration, error) {
		trialCounts[ttl]++
		switch ttl {
		case 3:
			return false, 50 * time.Millisecond, nil
		case 4:
			// Pass on 1st and 2nd trial, fail on 3rd
			return trialCounts[ttl] <= 2, 40 * time.Millisecond, nil
		case 5:
			return true, 30 * time.Millisecond, nil
		case 6:
			return true, 32 * time.Millisecond, nil
		case 7:
			return true, 35 * time.Millisecond, nil
		default:
			return false, 0, nil
		}
	}

	candidateTTLs := []uint8{3, 4, 5, 6, 7}
	dnsCheck := DNSCheckResult{Domain: "updates.discord.com"}

	result := TunePacketDomain(ctx, "updates.discord.com", 443, candidateTTLs, 3, 0, dnsCheck, probeMock)

	if !result.IsConclusive {
		t.Fatalf("expected conclusive result, got: %s", result.RecommendationReason)
	}
	if result.RecommendedTTL != 5 {
		t.Fatalf("RecommendedTTL = %d, want 5 (minimum working TTL)", result.RecommendedTTL)
	}

	report := FormatPacketReport([]PacketTuneResult{result})
	if !strings.Contains(report, "fake_ttl = 5") {
		t.Fatalf("expected 'fake_ttl = 5' in report, got:\n%s", report)
	}
	if !strings.Contains(report, "PASS (Optimal Min-TTL)") {
		t.Fatalf("expected 'PASS (Optimal Min-TTL)' in report, got:\n%s", report)
	}
}

func TestTunePacketDomain_LowestTTLPasses(t *testing.T) {
	ctx := context.Background()

	// Scenario: All TTLs from 3..7 succeed 100%
	// Expected selection: TTL 3 (minimum)
	probeMock := func(ctx context.Context, domain string, port int, ttl uint8) (bool, time.Duration, error) {
		return true, 20 * time.Millisecond, nil
	}

	candidateTTLs := []uint8{7, 6, 5, 4, 3} // Unsorted input to test sorting
	result := TunePacketDomain(ctx, "roblox.com", 443, candidateTTLs, 3, 0, DNSCheckResult{}, probeMock)

	if !result.IsConclusive {
		t.Fatalf("expected conclusive result, got: %s", result.RecommendationReason)
	}
	if result.RecommendedTTL != 3 {
		t.Fatalf("RecommendedTTL = %d, want 3 (minimum working TTL)", result.RecommendedTTL)
	}
}

func TestTunePacketDomain_InconclusiveWhenAllFail(t *testing.T) {
	ctx := context.Background()

	probeMock := func(ctx context.Context, domain string, port int, ttl uint8) (bool, time.Duration, error) {
		return false, 100 * time.Millisecond, nil
	}

	candidateTTLs := []uint8{3, 4, 5}
	result := TunePacketDomain(ctx, "blocked.example.com", 443, candidateTTLs, 3, 0, DNSCheckResult{}, probeMock)

	if result.IsConclusive {
		t.Fatalf("expected inconclusive result when all fail, got recommended TTL %d", result.RecommendedTTL)
	}
	if result.RecommendedTTL != 0 {
		t.Fatalf("RecommendedTTL = %d, want 0", result.RecommendedTTL)
	}

	report := FormatPacketReport([]PacketTuneResult{result})
	if !strings.Contains(report, "Inconclusive") {
		t.Fatalf("expected 'Inconclusive' in report, got:\n%s", report)
	}
}

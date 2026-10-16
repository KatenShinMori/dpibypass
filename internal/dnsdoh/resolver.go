package dnsdoh

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpibypass/internal/config"
)

// Resolver specifies the domain resolution interface used by the proxy dialer.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// DoHResolver coordinates DoH endpoint clients, caching, standards-compliant
// failure handling, and conditional system-resolver fallback.
type DoHResolver struct {
	cfg              config.DoHConfig
	clients          []*DoHClient
	cache            *Cache
	logger           *slog.Logger
	idCounter        atomic.Uint32
	endpointMu       sync.RWMutex
	endpointBackoffs map[string]time.Time
}

// NewResolver constructs and initializes a DoHResolver from configuration.
func NewResolver(cfg config.DoHConfig, logger *slog.Logger) (*DoHResolver, error) {
	if logger == nil {
		logger = slog.Default()
	}

	r := &DoHResolver{
		cfg:              cfg,
		cache:            NewCache(1024),
		logger:           logger,
		endpointBackoffs: make(map[string]time.Time),
	}

	if cfg.Enabled {
		if len(cfg.Endpoints) == 0 {
			return nil, errors.New("doh is enabled but no endpoints configured")
		}

		for i, ep := range cfg.Endpoints {
			client, err := NewDoHClient(ep, 5*time.Second)
			if err != nil {
				return nil, fmt.Errorf("initialize DoH endpoint %d (%q): %w", i, ep.URL, err)
			}
			r.clients = append(r.clients, client)
		}
	}

	return r, nil
}

// LookupIP resolves host to a slice of IP addresses.
// It detects IP literals immediately, checks the multi-category cache, queries configured
// DoH endpoints for A and AAAA records, and applies system-resolver fallback strictly on
// transport failures when configured.
func (r *DoHResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	// 1. IP literals require zero DNS queries
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if norm == "" {
		return nil, errors.New("empty host domain")
	}

	// If DoH is disabled, delegate directly to the system resolver
	if !r.cfg.Enabled {
		return r.lookupSystem(ctx, norm)
	}

	now := time.Now()

	// 2. Check cache for A and AAAA
	cachedA, errA, foundA := r.cache.Get(norm, TypeA, now)
	cachedAAAA, errAAAA, foundAAAA := r.cache.Get(norm, TypeAAAA, now)

	// If both are cached
	if foundA && foundAAAA {
		// If both are NXDOMAIN, return NXDOMAIN
		if errors.Is(errA, ErrNXDomain) && errors.Is(errAAAA, ErrNXDomain) {
			return nil, ErrNXDomain
		}
		// Combine cached addresses with IPv4 preference
		var combined []net.IP
		combined = append(combined, cachedA...)
		combined = append(combined, cachedAAAA...)
		if len(combined) > 0 {
			return orderIPs(combined), nil
		}
		if errA != nil {
			return nil, errA
		}
		if errAAAA != nil {
			return nil, errAAAA
		}
		return nil, ErrNoData
	}

	// 3. Resolve missing types via DoH
	var ipsA []net.IP
	var ipsAAAA []net.IP
	var dohTransportFailed bool
	var lastTransportErr error

	// Resolve Type A if not in cache
	if foundA {
		ipsA = cachedA
	} else {
		res, err, isTransErr := r.queryTypeWithFailover(ctx, norm, TypeA)
		if isTransErr {
			dohTransportFailed = true
			lastTransportErr = err
		} else if err == nil && res != nil {
			ipsA = res.IPs
			if res.TTL > 0 {
				r.cache.PutPositive(norm, TypeA, res.IPs, res.TTL, now)
			}
		} else if err != nil {
			if errors.Is(err, ErrNXDomain) || errors.Is(err, ErrNoData) {
				// Definitive negative answer: cache if SOA present
				if res != nil && res.HasSOA && res.NegativeTTL > 0 {
					r.cache.PutNegative(norm, TypeA, err, res.NegativeTTL, now)
				}
			} else if errors.Is(err, ErrServFail) || errors.Is(err, ErrFormErr) || errors.Is(err, ErrRefused) {
				// Transient DNS server failure: cache per RFC 9520 (clamped 1s..300s)
				r.cache.PutFailure(norm, TypeA, err, 5*time.Second, now)
			}
		}
	}

	// Resolve Type AAAA if not in cache
	if foundAAAA {
		ipsAAAA = cachedAAAA
	} else {
		res, err, isTransErr := r.queryTypeWithFailover(ctx, norm, TypeAAAA)
		if isTransErr {
			dohTransportFailed = true
			lastTransportErr = err
		} else if err == nil && res != nil {
			ipsAAAA = res.IPs
			if res.TTL > 0 {
				r.cache.PutPositive(norm, TypeAAAA, res.IPs, res.TTL, now)
			}
		} else if err != nil {
			if errors.Is(err, ErrNXDomain) || errors.Is(err, ErrNoData) {
				if res != nil && res.HasSOA && res.NegativeTTL > 0 {
					r.cache.PutNegative(norm, TypeAAAA, err, res.NegativeTTL, now)
				}
			} else if errors.Is(err, ErrServFail) || errors.Is(err, ErrFormErr) || errors.Is(err, ErrRefused) {
				r.cache.PutFailure(norm, TypeAAAA, err, 5*time.Second, now)
			}
		}
	}

	// Combine results
	var allIPs []net.IP
	allIPs = append(allIPs, ipsA...)
	allIPs = append(allIPs, ipsAAAA...)

	if len(allIPs) > 0 {
		return orderIPs(allIPs), nil
	}

	// 4. Handle Failure & Fallback
	// If DoH transport/service failed completely across all endpoints
	if dohTransportFailed && len(allIPs) == 0 {
		if r.cfg.FallbackSystem {
			r.logger.Warn("DoH endpoints unreachable or failed; falling back to system resolver",
				slog.String("target_domain", norm),
				slog.String("error_category", "doh_failed_system_fallback"),
			)
			return r.lookupSystem(ctx, norm)
		}
		return nil, fmt.Errorf("DoH resolution failed: %w", lastTransportErr)
	}

	// Authoritative negative response (NXDOMAIN / NODATA) - do NOT fall back to system
	return nil, ErrNoData
}

// queryTypeWithFailover sends a query for a specific QType across configured endpoints.
// It returns (*Response, err, isTransportError).
func (r *DoHResolver) queryTypeWithFailover(ctx context.Context, domain string, qtype uint16) (*Response, error, bool) {
	queryID := uint16(r.idCounter.Add(1))
	wireQuery, err := BuildQuery(domain, qtype, queryID)
	if err != nil {
		return nil, err, false
	}

	var lastErr error
	allTransportErrors := true

	now := time.Now()

	for _, client := range r.clients {
		epURL := client.EndpointURL()

		// Check endpoint backoff
		r.endpointMu.RLock()
		backoffUntil, inBackoff := r.endpointBackoffs[epURL]
		r.endpointMu.RUnlock()

		if inBackoff && now.Before(backoffUntil) {
			continue
		}

		wireResp, err := client.Query(ctx, wireQuery)
		if err != nil {
			lastErr = err
			// Record short transport backoff (3 seconds)
			r.endpointMu.Lock()
			r.endpointBackoffs[epURL] = now.Add(3 * time.Second)
			r.endpointMu.Unlock()
			continue
		}

		// Received wire response from DoH endpoint
		allTransportErrors = false

		parsedResp, parseErr := ParseResponse(wireResp, queryID, domain, qtype)
		if parseErr != nil {
			// Check if parsed error is definitive (NXDOMAIN, NODATA, SERVFAIL, etc.)
			if errors.Is(parseErr, ErrNXDomain) || errors.Is(parseErr, ErrNoData) ||
				errors.Is(parseErr, ErrServFail) || errors.Is(parseErr, ErrFormErr) ||
				errors.Is(parseErr, ErrRefused) {
				return parsedResp, parseErr, false
			}
			// Malformed response - try next endpoint
			lastErr = parseErr
			continue
		}

		return parsedResp, nil, false
	}

	if allTransportErrors {
		return nil, fmt.Errorf("all DoH endpoints failed: %w", lastErr), true
	}

	return nil, lastErr, false
}

// lookupSystem delegates resolution to Go's standard net.DefaultResolver.
func (r *DoHResolver) lookupSystem(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("system resolver lookup %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, ErrNoData
	}
	return orderIPs(ips), nil
}

// orderIPs sorts a slice of IP addresses placing IPv4 addresses first, followed by IPv6 addresses.
func orderIPs(ips []net.IP) []net.IP {
	var v4 []net.IP
	var v6 []net.IP

	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	res := make([]net.IP, 0, len(ips))
	res = append(res, v4...)
	res = append(res, v6...)
	return res
}

// SetRootCAs configures a custom root CA pool across all DoH endpoint clients for testing.
func (r *DoHResolver) SetRootCAs(pool *x509.CertPool) {
	for _, c := range r.clients {
		c.SetRootCAs(pool)
	}
}

// ResolveQueryType resolves a specific QType (TypeA or TypeAAAA) for a domain,
// checking the in-memory cache first and querying configured DoH endpoints on a miss.
// It returns (ips, effectiveTTL, isNoData, err).
func (r *DoHResolver) ResolveQueryType(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if norm == "" {
		return nil, 0, false, errors.New("empty host domain")
	}

	// 0. IP literals require zero DNS queries
	if ip := net.ParseIP(norm); ip != nil {
		if qtype == TypeA {
			if ip.To4() != nil {
				return []net.IP{ip}, 86400 * time.Second, false, nil
			}
			return nil, 86400 * time.Second, true, nil // NODATA for IPv6 literal queried for A
		} else if qtype == TypeAAAA {
			if ip.To4() == nil {
				return []net.IP{ip}, 86400 * time.Second, false, nil
			}
			return nil, 86400 * time.Second, true, nil // NODATA for IPv4 literal queried for AAAA
		}
		return nil, 0, false, fmt.Errorf("unsupported QType %d for IP literal", qtype)
	}

	if !r.cfg.Enabled {
		return nil, 0, false, errors.New("DoH resolver is disabled")
	}

	now := time.Now()

	// 1. Check in-memory cache for the requested QType
	cached, remTTL, err, found := r.cache.GetWithTTL(norm, qtype, now)
	if found {
		if err == nil && len(cached) > 0 {
			return cached, remTTL, false, nil
		}
		if errors.Is(err, ErrNoData) {
			return nil, remTTL, true, nil
		}
		if errors.Is(err, ErrNXDomain) {
			return nil, remTTL, false, ErrNXDomain
		}
		return nil, 0, false, err
	}

	// 2. Query configured DoH endpoints with failover
	res, err, isTransErr := r.queryTypeWithFailover(ctx, norm, qtype)
	if isTransErr {
		return nil, 0, false, err
	}
	if err == nil && res != nil {
		effectiveTTL := res.TTL
		if effectiveTTL <= 0 {
			effectiveTTL = 300 * time.Second
		}
		r.cache.PutPositive(norm, qtype, res.IPs, effectiveTTL, now)
		return res.IPs, effectiveTTL, false, nil
	}
	if err != nil {
		if errors.Is(err, ErrNoData) {
			negTTL := 60 * time.Second
			if res != nil && res.HasSOA && res.NegativeTTL > 0 {
				negTTL = res.NegativeTTL
			}
			r.cache.PutNegative(norm, qtype, err, negTTL, now)
			return nil, negTTL, true, nil
		}
		if errors.Is(err, ErrNXDomain) {
			negTTL := 60 * time.Second
			if res != nil && res.HasSOA && res.NegativeTTL > 0 {
				negTTL = res.NegativeTTL
			}
			r.cache.PutNegative(norm, qtype, err, negTTL, now)
			return nil, negTTL, false, ErrNXDomain
		}
		if errors.Is(err, ErrServFail) || errors.Is(err, ErrFormErr) || errors.Is(err, ErrRefused) {
			r.cache.PutFailure(norm, qtype, err, 5*time.Second, now)
		}
		return nil, 0, false, err
	}

	return nil, 60 * time.Second, true, nil
}

package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"dpibypass/internal/dnsdoh"
)

// Dialer abstracts upstream network connection dialing.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NetDialer implements Dialer using standard net.Dialer with configurable timeouts.
type NetDialer struct {
	Timeout time.Duration
}

// DialContext creates an outbound TCP connection using net.Dialer.
func (d *NetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: d.Timeout,
	}
	return dialer.DialContext(ctx, network, address)
}

// ResolvingDialer integrates domain resolution (via DoH or system fallback) with upstream TCP dialing.
// It detects IP literals and passes them directly to the base dialer without resolution.
// For domain names, it resolves candidate addresses (ordered with IPv4 preference) and performs
// bounded retries across the resolved IPs.
type ResolvingDialer struct {
	base     Dialer
	resolver dnsdoh.Resolver
	timeout  time.Duration
}

// NewResolvingDialer constructs a ResolvingDialer wrapping a base dialer and domain resolver.
func NewResolvingDialer(base Dialer, resolver dnsdoh.Resolver, timeout time.Duration) *ResolvingDialer {
	if base == nil {
		base = &NetDialer{Timeout: timeout}
	}
	return &ResolvingDialer{
		base:     base,
		resolver: resolver,
		timeout:  timeout,
	}
}

// DialContext dials the target address, resolving domain names via the configured resolver
// when the destination is not already an IP literal.
func (d *ResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return d.base.DialContext(ctx, network, address)
	}

	// 1. IP literals bypass DNS resolution entirely
	if ip := net.ParseIP(host); ip != nil {
		return d.base.DialContext(ctx, network, address)
	}

	// 2. If no custom resolver is configured, delegate directly to base dialer
	if d.resolver == nil {
		return d.base.DialContext(ctx, network, address)
	}

	// 3. Resolve host via domain resolver
	ips, err := d.resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve host %q: no addresses found", host)
	}

	// 4. Bounded sequential connection attempts across candidate IPs
	var lastErr error
	for _, ip := range ips {
		candidateAddr := net.JoinHostPort(ip.String(), port)
		conn, err := d.base.DialContext(ctx, network, candidateAddr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("dial all candidate addresses failed for %s: %w", address, lastErr)
}

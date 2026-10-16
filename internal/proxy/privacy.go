package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
)

// ClassifyError maps network and operational errors to high-level, privacy-safe categories.
// It avoids logging raw operating system error strings that may leak IP addresses, ports,
// hostnames, or system error descriptions.
func ClassifyError(err error) string {
	if err == nil {
		return "none"
	}

	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_resolution_failed"
	}

	// Fallback heuristic based on standard networking error phrases
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return "connection_refused"
	case strings.Contains(msg, "unreachable"):
		return "network_unreachable"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.Contains(msg, "reset"):
		return "connection_reset"
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "dns"):
		return "dns_resolution_failed"
	case strings.Contains(msg, "canceled") || strings.Contains(msg, "cancelled"):
		return "context_canceled"
	default:
		return "network_error"
	}
}

// TargetLogAttr extracts a privacy-compliant slog attribute for target destinations.
//
// Privacy rules:
// - If host is a domain name, it logs: slog.String("domain", <domain>)
// - If host is a literal IPv4 or IPv6 address, it logs: slog.String("target_type", "ip")
// - Destination ports are NEVER logged.
// - Full URLs or query parameters are NEVER logged.
func TargetLogAttr(target string) slog.Attr {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		return slog.String("target_type", "ip")
	}

	cleanDomain := strings.ToLower(host)
	if cleanDomain == "" {
		return slog.String("target_type", "unknown")
	}
	return slog.String("domain", cleanDomain)
}

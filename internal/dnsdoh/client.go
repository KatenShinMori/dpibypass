package dnsdoh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"dpibypass/internal/config"
)

// DoHClient represents an isolated HTTP client for a single DoH endpoint.
type DoHClient struct {
	endpoint     config.DoHEndpoint
	parsedURL    *url.URL
	httpClient   *http.Client
	bootstrapIPs []string
	ipIndex      atomic.Uint32
}

// NewDoHClient initializes an isolated DoHClient for the given endpoint configuration.
// It verifies that bootstrap IPs are present for hostname-based endpoints and strictly
// configures TLS certificate verification with ServerName set to the endpoint host.
func NewDoHClient(ep config.DoHEndpoint, timeout time.Duration) (*DoHClient, error) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL %q: %w", ep.URL, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid DoH URL scheme %q (strictly https required)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("empty hostname in DoH URL %q", ep.URL)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	isIP := net.ParseIP(host) != nil
	bootstrapIPs := make([]string, 0, len(ep.BootstrapIPs))
	for _, ipStr := range ep.BootstrapIPs {
		if net.ParseIP(ipStr) == nil {
			return nil, fmt.Errorf("invalid bootstrap IP %q for endpoint %q", ipStr, ep.URL)
		}
		bootstrapIPs = append(bootstrapIPs, ipStr)
	}

	if isIP {
		if len(bootstrapIPs) == 0 {
			bootstrapIPs = []string{host}
		}
	} else {
		if len(bootstrapIPs) == 0 {
			switch strings.ToLower(host) {
			case "cloudflare-dns.com", "one.one.one.one":
				bootstrapIPs = []string{"1.1.1.1", "1.0.0.1"}
			case "dns.google":
				bootstrapIPs = []string{"8.8.8.8", "8.8.4.4"}
			default:
				return nil, fmt.Errorf("endpoint %q requires at least one bootstrap IP", ep.URL)
			}
		}
	}

	client := &DoHClient{
		endpoint:     ep,
		parsedURL:    parsed,
		bootstrapIPs: bootstrapIPs,
	}

	// Create custom transport with isolated dialer and strict TLS verification
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, // Strictly verify certificates against standard root CAs
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("DoH client must never invoke DNS resolver")
			},
		},
	}

	dialTCP := func(ctx context.Context) (net.Conn, error) {
		n := len(client.bootstrapIPs)
		if n == 0 {
			return nil, errors.New("no bootstrap IP available")
		}
		var lastErr error
		for i := 0; i < n; i++ {
			idx := int(client.ipIndex.Add(1)-1) % n
			bootstrapIP := client.bootstrapIPs[idx]
			targetAddr := net.JoinHostPort(bootstrapIP, port)
			conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}

	var transport *http.Transport
	transport = &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTCP(ctx)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			n := len(client.bootstrapIPs)
			if n == 0 {
				n = 1
			}
			var lastErr error
			for i := 0; i < n; i++ {
				rawConn, err := dialTCP(ctx)
				if err != nil {
					lastErr = err
					continue
				}
				cfg := transport.TLSClientConfig
				if cfg == nil {
					cfg = tlsConfig
				}
				tlsConn := tls.Client(rawConn, cfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = rawConn.Close()
					lastErr = err
					continue
				}
				return tlsConn, nil
			}
			return nil, lastErr
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client.httpClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Strictly reject HTTP redirects for DoH requests (do not follow 3xx)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

// EndpointURL returns the endpoint's configured URL.
func (c *DoHClient) EndpointURL() string {
	return c.endpoint.URL
}

// Query transmits a binary wire-format DNS query over HTTPS via POST and returns the validated binary response.
func (c *DoHClient) Query(ctx context.Context, wireQuery []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.URL, bytes.NewReader(wireQuery))
	if err != nil {
		return nil, fmt.Errorf("construct DoH request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute DoH request: %w", err)
	}
	defer resp.Body.Close()

	// Reject 3xx redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("unexpected HTTP redirect %d from DoH endpoint", resp.StatusCode)
	}

	// Reject non-200 responses
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from DoH endpoint", resp.StatusCode)
	}

	// Validate media type strictly equals application/dns-message
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/dns-message" {
		return nil, fmt.Errorf("invalid response Content-Type %q (expected application/dns-message)", contentType)
	}

	// Read response with strict upper bound limit (64 KB)
	lr := io.LimitReader(resp.Body, int64(MaxDNSMessageBytes+1))
	respBody, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read DoH response body: %w", err)
	}
	if len(respBody) > MaxDNSMessageBytes {
		return nil, fmt.Errorf("DoH response size %d exceeded maximum bound %d", len(respBody), MaxDNSMessageBytes)
	}

	return respBody, nil
}

// SetRootCAs allows configuring a custom root CA pool for verification in tests.
// InsecureSkipVerify remains strictly false.
func (c *DoHClient) SetRootCAs(pool *x509.CertPool) {
	if tr, ok := c.httpClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.RootCAs = pool
	}
}

package diagnostics

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/strategy"
)

const (
	DefaultPort             = 443
	DefaultDialTimeout      = 5 * time.Second
	DefaultDNSTimeout       = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultHTTPTimeout      = 5 * time.Second
	DefaultMaxHeaderBytes   = 16 * 1024 // 16 KiB bounded header limit per decision
)

// Resolver defines the DNS resolution interface for diagnostics.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type defaultSysResolver struct{}

func (defaultSysResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// CheckerConfig defines operational bounds and dependencies for diagnostic checks.
type CheckerConfig struct {
	DialTimeout      time.Duration
	DNSTimeout       time.Duration
	HandshakeTimeout time.Duration
	HTTPTimeout      time.Duration
	MaxHeaderBytes   int
	PlainHTTP        bool           // Optional: force plain HTTP probe (port 80 is always plain HTTP)
	RootCAs          *x509.CertPool // Optional root CA pool (nil uses system pool)
	Resolver         Resolver       // Optional custom resolver (nil uses net.DefaultResolver)
}

// DefaultCheckerConfig returns safe, bounded settings for diagnostics.
func DefaultCheckerConfig() CheckerConfig {
	return CheckerConfig{
		DialTimeout:      DefaultDialTimeout,
		DNSTimeout:       DefaultDNSTimeout,
		HandshakeTimeout: DefaultHandshakeTimeout,
		HTTPTimeout:      DefaultHTTPTimeout,
		MaxHeaderBytes:   DefaultMaxHeaderBytes,
	}
}

// RunCheck executes an end-to-end connectivity check for target domain:port using the specified strategy.
// It exercises DNS resolution, TCP dial, TLS handshake (with strategy applied), and minimal GET / HTTP probe.
func RunCheck(
	ctx context.Context,
	domain string,
	port int,
	strat strategy.Strategy,
	cfg CheckerConfig,
) CheckResult {
	startTotal := time.Now()
	res := CheckResult{
		Domain:       domain,
		Port:         port,
		StrategyName: "none",
	}
	if strat != nil {
		res.StrategyName = strat.Name()
	}

	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = DefaultDNSTimeout
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}

	// 1. Validate domain and port
	normDomain := config.NormalizeDomain(domain)
	if normDomain == "" || strings.Contains(normDomain, "*") || port <= 0 || port > 65535 {
		res.Outcome = OutcomeInvalidConfig
		res.FailureReason = fmt.Sprintf("invalid domain %q or port %d", domain, port)
		res.TotalDuration = time.Since(startTotal)
		return res
	}

	// Strategy applicability validation
	isTLS := (port != 80 && !cfg.PlainHTTP)
	if isTLS && strat != nil && strat.Name() == "http-host-tweak" {
		res.Outcome = OutcomeUnsupportedStrategy
		res.FailureReason = "http-host-tweak is a plaintext HTTP strategy and cannot be applied to TLS ClientHello streams"
		res.TotalDuration = time.Since(startTotal)
		return res
	}

	if !isTLS && strat != nil && strat.Name() != "none" && strat.Name() != "http-host-tweak" {
		res.Outcome = OutcomeUnsupportedStrategy
		res.FailureReason = fmt.Sprintf("%s is a TLS strategy and cannot be applied to plain HTTP", strat.Name())
		res.TotalDuration = time.Since(startTotal)
		return res
	}

	// 2. DNS Resolution
	startDNS := time.Now()
	var targetIPs []string
	if ip := net.ParseIP(normDomain); ip != nil {
		targetIPs = []string{ip.String()}
	} else {
		dnsCtx, dnsCancel := context.WithTimeout(ctx, cfg.DNSTimeout)
		defer dnsCancel()

		resolver := cfg.Resolver
		if resolver == nil {
			resolver = defaultSysResolver{}
		}

		ips, err := resolver.LookupIP(dnsCtx, normDomain)
		res.DNSDuration = time.Since(startDNS)
		if err != nil {
			res.Outcome = classifyDNSError(err)
			res.FailureReason = fmt.Sprintf("DNS lookup failed: %v", err)
			res.TotalDuration = time.Since(startTotal)
			return res
		}
		if len(ips) == 0 {
			res.Outcome = OutcomeDNSFailure
			res.FailureReason = "DNS returned no IP addresses"
			res.TotalDuration = time.Since(startTotal)
			return res
		}
		for _, ip := range ips {
			targetIPs = append(targetIPs, ip.String())
		}
	}
	res.ResolvedIPs = targetIPs
	res.SelectedIP = targetIPs[0]

	// 3. TCP Dial
	targetAddr := net.JoinHostPort(res.SelectedIP, strconv.Itoa(port))
	startTCP := time.Now()

	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	dialCtx, dialCancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer dialCancel()

	rawConn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	res.TCPDuration = time.Since(startTCP)
	if err != nil {
		res.Outcome = classifyDialError(err)
		res.FailureReason = fmt.Sprintf("TCP dial to %s failed: %v", targetAddr, err)
		res.TotalDuration = time.Since(startTotal)
		return res
	}
	defer rawConn.Close()

	// 4. Transport & Protocol Probe
	if isTLS {
		// Wrap connection in production StrategyConn
		stratConn := NewStrategyConn(ctx, rawConn, strat)

		startTLS := time.Now()
		tlsConfig := &tls.Config{
			ServerName:         normDomain,
			RootCAs:            cfg.RootCAs,
			InsecureSkipVerify: false, // Strict certificate verification unconditionally
		}

		tlsClient := tls.Client(stratConn, tlsConfig)
		defer tlsClient.Close()

		hsCtx, hsCancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
		defer hsCancel()

		if err := tlsClient.HandshakeContext(hsCtx); err != nil {
			res.TLSDuration = time.Since(startTLS)
			res.StrategyApplied = stratConn.Applied()
			res.Outcome = classifyTLSError(err)
			res.FailureReason = fmt.Sprintf("TLS handshake failed: %v", err)
			res.TotalDuration = time.Since(startTotal)
			return res
		}
		res.TLSDuration = time.Since(startTLS)
		res.StrategyApplied = stratConn.Applied()

		// If a non-none strategy was requested but fell back to none during execution,
		// do not disguise the fallback as a valid strategy execution.
		if strat != nil && strat.Name() != "none" && stratConn.IsFallback() {
			res.Outcome = OutcomeUnsupportedStrategy
			res.FailureReason = fmt.Sprintf("strategy %q could not be applied: %s", strat.Name(), stratConn.FallbackReason())
			res.TotalDuration = time.Since(startTotal)
			return res
		}

		// 5. Minimal HTTP GET / probe over TLS
		probeErr := runHTTPProbe(ctx, tlsClient, normDomain, cfg.HTTPTimeout, cfg.MaxHeaderBytes, &res)
		if probeErr != nil {
			res.FailureReason = probeErr.Error()
		}
	} else {
		// Plain HTTP probe (port 80)
		startHTTP := time.Now()
		req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: dpibypass-diagnostics/0.1\r\nConnection: close\r\n\r\n", normDomain)

		if strat != nil && strat.Name() == "http-host-tweak" {
			if hostStrat, ok := strat.(*strategy.HTTPHostTweakStrategy); ok {
				transformed, chunks := hostStrat.TransformHeaders(req)
				plan := strategy.ExecutionPlan{
					StrategyName: strat.Name(),
					Chunks:       chunks,
				}
				if len(chunks) == 0 {
					plan.Chunks = []strategy.WriteChunk{{Data: []byte(transformed)}}
				}
				_, err := strategy.Execute(ctx, rawConn, plan)
				if err != nil {
					res.StrategyApplied = false
					res.Outcome = OutcomeConnectionReset
					res.FailureReason = fmt.Sprintf("write plain HTTP request: %v", err)
					res.TotalDuration = time.Since(startTotal)
					return res
				}
				res.StrategyApplied = true
			}
		} else {
			// none baseline
			res.StrategyApplied = false
			if _, err := rawConn.Write([]byte(req)); err != nil {
				res.Outcome = OutcomeConnectionReset
				res.FailureReason = fmt.Sprintf("write plain HTTP request: %v", err)
				res.TotalDuration = time.Since(startTotal)
				return res
			}
		}

		probeErr := readHTTPResponseHeaders(rawConn, cfg.HTTPTimeout, cfg.MaxHeaderBytes, &res)
		res.HTTPDuration = time.Since(startHTTP)
		if probeErr != nil {
			res.FailureReason = probeErr.Error()
		}
	}

	res.TotalDuration = time.Since(startTotal)
	return res
}

func runHTTPProbe(
	ctx context.Context,
	conn net.Conn,
	domain string,
	timeout time.Duration,
	maxHeaderBytes int,
	res *CheckResult,
) error {
	startHTTP := time.Now()

	// Minimal GET / request
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: dpibypass-diagnostics/0.1\r\nConnection: close\r\n\r\n", domain)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		res.HTTPDuration = time.Since(startHTTP)
		res.Outcome = OutcomeConnectionReset
		return fmt.Errorf("write HTTP request: %w", err)
	}

	err := readHTTPResponseHeaders(conn, timeout, maxHeaderBytes, res)
	res.HTTPDuration = time.Since(startHTTP)
	return err
}

func readHTTPResponseHeaders(
	conn net.Conn,
	timeout time.Duration,
	maxHeaderBytes int,
	res *CheckResult,
) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	// Read status line
	statusLine, err := readBoundedLine(br, maxHeaderBytes)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			res.Outcome = OutcomeTimeout
			return fmt.Errorf("read HTTP status line timeout: %w", err)
		}
		if errors.Is(err, io.EOF) || isResetError(err) {
			res.Outcome = OutcomeConnectionReset
			return fmt.Errorf("connection closed/reset before HTTP response: %w", err)
		}
		res.Outcome = OutcomeHTTPResponseInvalid
		return fmt.Errorf("read HTTP status line: %w", err)
	}

	fields := strings.Fields(statusLine)
	if len(fields) < 2 || !strings.HasPrefix(strings.ToUpper(fields[0]), "HTTP/") {
		res.Outcome = OutcomeHTTPResponseInvalid
		return fmt.Errorf("malformed HTTP status line %q", statusLine)
	}

	code, err := strconv.Atoi(fields[1])
	if err != nil {
		res.Outcome = OutcomeHTTPResponseInvalid
		return fmt.Errorf("invalid HTTP status code %q", fields[1])
	}
	res.HTTPStatusCode = code

	// Read remaining headers up to maxHeaderBytes limit; DO NOT read response body
	totalBytes := len(statusLine)
	for {
		headerLine, err := readBoundedLine(br, maxHeaderBytes-totalBytes)
		if err != nil {
			res.Outcome = OutcomeHTTPResponseInvalid
			return fmt.Errorf("read response headers: %w", err)
		}
		totalBytes += len(headerLine)
		if totalBytes > maxHeaderBytes {
			res.Outcome = OutcomeHTTPResponseInvalid
			return errors.New("HTTP response headers exceeded maximum limit (16 KiB)")
		}
		if headerLine == "" || headerLine == "\r" {
			break
		}
	}

	// Classify based on HTTP status code
	if code == 403 || code == 451 {
		res.Outcome = OutcomeHTTPRestricted
		return nil
	}

	res.Outcome = OutcomeSuccess
	return nil
}

func readBoundedLine(br *bufio.Reader, maxBytes int) (string, error) {
	var line []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return string(line), err
		}
		if b == '\n' {
			n := len(line)
			if n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return string(line), nil
		}
		line = append(line, b)
		if len(line) > maxBytes {
			return "", errors.New("line length exceeded limit (16 KiB)")
		}
	}
}

func classifyDNSError(err error) Outcome {
	if errors.Is(err, context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	return OutcomeDNSFailure
}

func classifyDialError(err error) Outcome {
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		return OutcomeTimeout
	}
	if isResetError(err) {
		return OutcomeConnectionReset
	}
	return OutcomeTCPConnectionFailure
}

func classifyTLSError(err error) Outcome {
	var x509Unknown x509.UnknownAuthorityError
	var x509Hostname x509.HostnameError
	var x509Invalid x509.CertificateInvalidError

	if errors.As(err, &x509Unknown) || errors.As(err, &x509Hostname) || errors.As(err, &x509Invalid) {
		return OutcomeCertVerificationFailure
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		return OutcomeTimeout
	}
	if isResetError(err) {
		return OutcomeConnectionReset
	}
	return OutcomeTLSHandshakeFailure
}

func isResetError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	str := strings.ToLower(err.Error())
	return strings.Contains(str, "connection reset") ||
		strings.Contains(str, "wsarecv") ||
		strings.Contains(str, "wsasend") ||
		strings.Contains(str, "forcibly closed")
}

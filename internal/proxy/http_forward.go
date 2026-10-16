package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"dpibypass/internal/strategy"
)

// HandleHTTPForward processes plain unencrypted HTTP proxy requests using absolute-form request targets.
// E.g., "GET http://example.com/path HTTP/1.1" -> dials example.com:80, forwards rewritten request "GET /path HTTP/1.1".
func HandleHTTPForward(
	ctx context.Context,
	clientConn net.Conn,
	br *bufio.Reader,
	reqLine string,
	dialer Dialer,
	logger *slog.Logger,
	cfg HandlerConfig,
) error {
	parts := strings.Fields(reqLine)
	if len(parts) != 3 {
		sendHTTPError(clientConn, 400, "Bad Request")
		return fmt.Errorf("malformed plain HTTP request line: %q", reqLine)
	}

	method := strings.ToUpper(parts[0])
	rawURL := parts[1]
	proto := strings.ToUpper(parts[2])

	parsedURL, err := url.Parse(rawURL)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" {
		sendHTTPError(clientConn, 400, "Bad Request: absolute URL required for proxy forwarding")
		return fmt.Errorf("plain HTTP proxy requires absolute URL, got %q", rawURL)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "80"
	}
	targetAddr := net.JoinHostPort(host, port)

	// Rewrite request URI to origin-form (e.g. /path?query)
	originURI := parsedURL.RequestURI()
	if originURI == "" {
		originURI = "/"
	}
	rewrittenReqLine := fmt.Sprintf("%s %s %s\r\n", method, originURI, proto)

	// Read remaining headers until empty line
	headerBuf := strings.Builder{}
	headerBuf.WriteString(rewrittenReqLine)

	totalHeaderBytes := len(rewrittenReqLine)
	for {
		line, err := readBoundedLine(br, maxHTTPHeaderBytes-totalHeaderBytes)
		if err != nil {
			sendHTTPError(clientConn, 400, "Bad Request")
			return fmt.Errorf("read plain HTTP header line: %w", err)
		}
		totalHeaderBytes += len(line)
		if totalHeaderBytes > maxHTTPHeaderBytes {
			sendHTTPError(clientConn, 431, "Request Header Fields Too Large")
			return errors.New("headers exceeded 16 KB")
		}

		if line == "" || line == "\r" {
			headerBuf.WriteString("\r\n")
			break
		}

		// Strip Proxy-Connection header if present
		if strings.HasPrefix(strings.ToLower(line), "proxy-connection:") {
			continue
		}

		headerBuf.WriteString(line)
		headerBuf.WriteString("\r\n")
	}

	// Dial upstream
	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	upstreamConn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		logger.Warn("plain http upstream dial failed",
			TargetLogAttr(host),
			slog.String("error_category", ClassifyError(err)),
		)
		sendHTTPError(clientConn, 502, "Bad Gateway")
		return fmt.Errorf("dial upstream %s: %w", targetAddr, err)
	}

	rawHeaders := headerBuf.String()
	if strings.ToLower(strings.TrimSpace(cfg.DefaultProfile.Type)) == "http-host-tweak" {
		tweakStrat := strategy.NewHTTPHostTweakStrategy(
			cfg.DefaultProfile.HostHeaderTweak,
			time.Duration(cfg.DefaultProfile.DelayMS)*time.Millisecond,
		)
		transformed, chunks := tweakStrat.TransformHeaders(rawHeaders)
		if len(chunks) > 0 {
			plan := strategy.ExecutionPlan{
				StrategyName: "http-host-tweak",
				Chunks:       chunks,
			}
			if _, err := strategy.Execute(ctx, upstreamConn, plan); err != nil {
				_ = upstreamConn.Close()
				return fmt.Errorf("forward tweaked headers to upstream: %w", err)
			}
		} else {
			if _, err := upstreamConn.Write([]byte(transformed)); err != nil {
				_ = upstreamConn.Close()
				return fmt.Errorf("forward tweaked headers to upstream: %w", err)
			}
		}
	} else {
		if _, err := upstreamConn.Write([]byte(rawHeaders)); err != nil {
			_ = upstreamConn.Close()
			return fmt.Errorf("forward headers to upstream: %w", err)
		}
	}

	// Drain any remaining buffered bytes from client
	var preBuffered []byte
	if br.Buffered() > 0 {
		preBuffered = make([]byte, br.Buffered())
		if _, err := io.ReadFull(br, preBuffered); err != nil {
			_ = upstreamConn.Close()
			return fmt.Errorf("drain pre-buffered bytes: %w", err)
		}
	}

	// Enter bidirectional relay
	return BidirectionalRelay(ctx, clientConn, upstreamConn, preBuffered, RelayConfig{
		IdleTimeout: cfg.IdleTimeout,
	})
}

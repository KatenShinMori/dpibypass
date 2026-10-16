package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"dpibypass/internal/config"
)

// HandlerConfig holds configuration values required by the connection handler.
type HandlerConfig struct {
	DialTimeout              time.Duration
	IdleTimeout              time.Duration
	InitialInspectionTimeout time.Duration
	MaxInitialBytes          int
	DefaultProfile           config.ProfileConfig
	Profiles                 map[string]config.ProfileConfig
	Matcher                  *config.DomainMatcher
}

// ServeConn inspects the first byte(s) of an accepted client connection,
// detects whether it is SOCKS5 or HTTP, and dispatches to the appropriate protocol handler.
// Any unrecognized protocol is safely rejected and closed.
func ServeConn(
	ctx context.Context,
	conn net.Conn,
	dialer Dialer,
	logger *slog.Logger,
	cfg HandlerConfig,
) error {
	defer conn.Close()

	br := bufio.NewReader(conn)

	// Peek the first byte to detect protocol
	firstByte, err := br.Peek(1)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("peek protocol initial byte: %w", err)
	}

	b := firstByte[0]

	// 1. SOCKS5 protocol starts with 0x05
	if b == socks5Version {
		return HandleSOCKS5(ctx, conn, br, dialer, logger, cfg)
	}

	// 2. HTTP proxy requests start with ASCII letters (e.g. 'C' for CONNECT, 'G' for GET, etc.)
	if isASCIIAlpha(b) {
		// Read first line to distinguish CONNECT from plain HTTP forwarding
		reqLine, err := readBoundedLine(br, maxHTTPHeaderBytes)
		if err != nil {
			sendHTTPError(conn, 400, "Bad Request")
			return fmt.Errorf("read HTTP request line: %w", err)
		}

		fields := strings.Fields(reqLine)
		if len(fields) < 3 {
			sendHTTPError(conn, 400, "Bad Request")
			return fmt.Errorf("malformed HTTP request line: %q", reqLine)
		}

		method := strings.ToUpper(fields[0])
		if method == "CONNECT" {
			// Re-inject request line so HandleHTTPConnect can parse it, or construct a reader
			combinedReader := bufio.NewReader(newPrefixedReader([]byte(reqLine+"\r\n"), br))
			return HandleHTTPConnect(ctx, conn, combinedReader, dialer, logger, cfg)
		}

		// Plain HTTP request (GET, POST, etc.)
		return HandleHTTPForward(ctx, conn, br, reqLine, dialer, logger, cfg)
	}

	// 3. Unrecognized protocol: reject safely without logging binary payload data, byte values, or client IP addresses
	logger.Warn("rejected connection with unrecognized protocol header",
		slog.String("error_category", "unrecognized_protocol"),
	)
	return fmt.Errorf("unrecognized protocol initial byte 0x%02x", b)
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// prefixedReader prepends prefix bytes before reading from reader r.
type prefixedReader struct {
	prefix []byte
	offset int
	r      *bufio.Reader
}

func newPrefixedReader(prefix []byte, r *bufio.Reader) *prefixedReader {
	return &prefixedReader{
		prefix: prefix,
		r:      r,
	}
}

func (pr *prefixedReader) Read(p []byte) (int, error) {
	if pr.offset < len(pr.prefix) {
		n := copy(p, pr.prefix[pr.offset:])
		pr.offset += n
		return n, nil
	}
	return pr.r.Read(p)
}

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

const maxHTTPHeaderBytes = 16 * 1024 // 16 KB bounded header limit

// HandleHTTPConnect processes an HTTP CONNECT tunnelling request.
func HandleHTTPConnect(
	ctx context.Context,
	clientConn net.Conn,
	br *bufio.Reader,
	dialer Dialer,
	logger *slog.Logger,
	cfg HandlerConfig,
) error {
	// 1. Read request line with strict bound
	reqLine, err := readBoundedLine(br, maxHTTPHeaderBytes)
	if err != nil {
		sendHTTPError(clientConn, 400, "Bad Request")
		return fmt.Errorf("read HTTP request line: %w", err)
	}

	parts := strings.Fields(reqLine)
	if len(parts) != 3 {
		sendHTTPError(clientConn, 400, "Bad Request")
		return fmt.Errorf("malformed HTTP request line: %q", reqLine)
	}

	method := strings.ToUpper(parts[0])
	target := parts[1]
	proto := strings.ToUpper(parts[2])

	if method != "CONNECT" {
		sendHTTPError(clientConn, 405, "Method Not Allowed")
		return fmt.Errorf("unsupported HTTP method %q (expected CONNECT)", method)
	}

	if !strings.HasPrefix(proto, "HTTP/") {
		sendHTTPError(clientConn, 400, "Bad Request")
		return fmt.Errorf("unsupported protocol %q", proto)
	}

	// 2. Consume and validate headers until empty line, enforcing size bound
	totalHeaderBytes := len(reqLine)
	for {
		headerLine, err := readBoundedLine(br, maxHTTPHeaderBytes-totalHeaderBytes)
		if err != nil {
			sendHTTPError(clientConn, 400, "Bad Request")
			return fmt.Errorf("read header line: %w", err)
		}
		totalHeaderBytes += len(headerLine)
		if totalHeaderBytes > maxHTTPHeaderBytes {
			sendHTTPError(clientConn, 431, "Request Header Fields Too Large")
			return errors.New("HTTP headers exceeded maximum limit (16 KB)")
		}
		if headerLine == "" || headerLine == "\r" {
			break
		}
	}

	// 3. Validate target authority (host:port)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// If port is missing, return 400
		sendHTTPError(clientConn, 400, "Bad Request: target must include port")
		return fmt.Errorf("invalid CONNECT target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		sendHTTPError(clientConn, 400, "Bad Request: invalid port")
		return fmt.Errorf("invalid port in CONNECT target %q", target)
	}
	targetAddr := net.JoinHostPort(host, portStr)

	logger.Debug("http connect target requested",
		TargetLogAttr(host),
	)

	// 4. Dial Upstream
	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	upstreamConn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		logger.Warn("http connect upstream dial failed",
			TargetLogAttr(host),
			slog.String("error_category", ClassifyError(err)),
		)
		sendHTTPError(clientConn, 502, "Bad Gateway")
		return fmt.Errorf("dial upstream %s: %w", targetAddr, err)
	}

	// 5. Send 200 Connection Established
	successResp := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(successResp)); err != nil {
		_ = upstreamConn.Close()
		return fmt.Errorf("send 200 Connection Established: %w", err)
	}

	// 6. Drain any client bytes already read into bufio.Reader (e.g. early ClientHello)
	var preBuffered []byte
	if br.Buffered() > 0 {
		preBuffered = make([]byte, br.Buffered())
		if _, err := io.ReadFull(br, preBuffered); err != nil {
			_ = upstreamConn.Close()
			return fmt.Errorf("drain pre-buffered bytes: %w", err)
		}
	}

	// 7. Enter Strategy Execution and Bidirectional Relay
	return ExecuteStrategyAndRelay(ctx, clientConn, upstreamConn, preBuffered, host, logger, cfg)
}

// readBoundedLine reads a single line up to maxBytes to avoid memory exhaustion on malformed streams.
func readBoundedLine(br *bufio.Reader, maxBytes int) (string, error) {
	var line []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			// Strip trailing '\r' if present
			n := len(line)
			if n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return string(line), nil
		}
		line = append(line, b)
		if len(line) > maxBytes {
			return "", errors.New("line length exceeded limit")
		}
	}
}

// sendHTTPError writes a standard HTTP error response to the client.
func sendHTTPError(w io.Writer, statusCode int, statusText string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%d %s\r\n",
		statusCode, statusText, statusCode, statusText)
	_, _ = w.Write([]byte(resp))
}

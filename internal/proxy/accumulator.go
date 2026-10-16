package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"dpibypass/internal/tlsparse"
)

// AccumulateInitialData gathers initial application bytes from clientConn starting with any preBuffered
// bytes. It parses incrementally with tlsparse to detect a complete TLS ClientHello.
// It stops immediately when a complete message is parsed, when non-TLS data is detected, when maxBytes
// is reached, or when the inspection timeout expires.
// Zero-byte-loss invariant: all read bytes are strictly preserved in their original order.
func AccumulateInitialData(
	ctx context.Context,
	clientConn net.Conn,
	preBuffered []byte,
	timeout time.Duration,
	maxBytes int,
) ([]byte, tlsparse.ParseResult, error) {
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	if timeout <= 0 {
		timeout = 1000 * time.Millisecond
	}

	buf := append([]byte(nil), preBuffered...)

	for {
		if ctx.Err() != nil {
			return buf, tlsparse.ParseResult{Status: tlsparse.StatusMalformed, Reason: "context_cancelled"}, ctx.Err()
		}

		// Evaluate what we have accumulated so far
		if len(buf) > 0 {
			res := tlsparse.ParseClientHello(buf, tlsparse.DefaultLimits())
			switch res.Status {
			case tlsparse.StatusParsed:
				// Complete ClientHello resolved!
				return buf, res, nil

			case tlsparse.StatusNotTLS, tlsparse.StatusNotClientHello, tlsparse.StatusMalformed, tlsparse.StatusLimitExceeded:
				// Data is conclusively not a pending ClientHello. Cease accumulation and forward as-is.
				return buf, res, nil

			case tlsparse.StatusNeedMoreData:
				// Need more bytes to complete record or handshake
			}
		}

		if len(buf) >= maxBytes {
			return buf, tlsparse.ParseResult{
				Status: tlsparse.StatusLimitExceeded,
				Reason: "max_initial_bytes_reached",
			}, nil
		}

		// Read additional bytes from socket with inspection deadline
		readBuf := make([]byte, 4096)
		toRead := maxBytes - len(buf)
		if toRead < len(readBuf) {
			readBuf = make([]byte, toRead)
		}

		_ = clientConn.SetReadDeadline(time.Now().Add(timeout))
		n, err := clientConn.Read(readBuf)
		_ = clientConn.SetReadDeadline(time.Time{}) // Clear deadline

		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err) {
				// Inspection timeout expired: cease accumulation and return what we have
				return buf, tlsparse.ParseResult{
					Status: tlsparse.StatusNeedMoreData,
					Reason: "inspection_timeout",
				}, nil
			}

			// For socket close or EOF, return whatever bytes we have gathered
			if len(buf) > 0 {
				return buf, tlsparse.ParseResult{
					Status: tlsparse.StatusNeedMoreData,
					Reason: "client_disconnected_during_inspection",
				}, nil
			}
			return nil, tlsparse.ParseResult{Status: tlsparse.StatusMalformed, Reason: "read_error"}, err
		}

		if n > 0 {
			buf = append(buf, readBuf[:n]...)
		}
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// closeWriter is implemented by connections that support half-closing their write side (e.g. *net.TCPConn).
type closeWriter interface {
	CloseWrite() error
}

// RelayConfig specifies operational parameters for bidirectional stream copying.
type RelayConfig struct {
	IdleTimeout time.Duration
	BufferSize  int
}

const defaultBufferSize = 32 * 1024 // 32 KB

// BidirectionalRelay copies data between client and upstream connections.
// Any initialBuffered bytes from the client reader are written to upstream first.
// It handles TCP half-close using CloseWrite() where supported and enforces idle timeouts.
// When ctx is cancelled, it immediately closes both connections to unblock active relay goroutines.
func BidirectionalRelay(ctx context.Context, client, upstream net.Conn, initialBuffered []byte, cfg RelayConfig) error {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}

	// Unblock relay immediately if ctx is cancelled
	stopRelay := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
		case <-stopRelay:
		}
	}()
	defer close(stopRelay)

	// 1. Flush any client bytes buffered prior to entering the relay.
	if len(initialBuffered) > 0 {
		if cfg.IdleTimeout > 0 {
			_ = upstream.SetWriteDeadline(time.Now().Add(cfg.IdleTimeout))
		}
		if _, err := upstream.Write(initialBuffered); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return err
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var errClientToUpstream error
	var errUpstreamToClient error

	// Goroutine 1: Client -> Upstream
	go func() {
		defer wg.Done()
		errClientToUpstream = copyHalf(client, upstream, bufSize, cfg.IdleTimeout)
	}()

	// Goroutine 2: Upstream -> Client
	go func() {
		defer wg.Done()
		errUpstreamToClient = copyHalf(upstream, client, bufSize, cfg.IdleTimeout)
	}()

	// Wait for both directions to finish
	wg.Wait()

	// Ensure both sides are completely closed after relay completes
	_ = client.Close()
	_ = upstream.Close()

	if errClientToUpstream != nil && !isNormalClose(errClientToUpstream) {
		return errClientToUpstream
	}
	if errUpstreamToClient != nil && !isNormalClose(errUpstreamToClient) {
		return errUpstreamToClient
	}

	return nil
}

// copyHalf copies data from src to dst until EOF or error.
// Upon encountering EOF on src, it signals half-close on dst via CloseWrite() if supported.
func copyHalf(src, dst net.Conn, bufSize int, idleTimeout time.Duration) error {
	buf := make([]byte, bufSize)

	for {
		if idleTimeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		nr, readErr := src.Read(buf)
		if nr > 0 {
			if idleTimeout > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			}
			nw, writeErr := dst.Write(buf[:nr])
			if writeErr != nil {
				return writeErr
			}
			if nw < nr {
				return io.ErrShortWrite
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				// Signal half-close to the other side if supported
				if cw, ok := dst.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
				return nil
			}
			return readErr
		}
	}
}

// isNormalClose checks if an error represents a normal connection termination.
func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// Check common network closed messages
	msg := err.Error()
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		containsClosedSubstring(msg)
}

func containsClosedSubstring(msg string) bool {
	return msg == "use of closed network connection" ||
		msg == "wsarecv: An established connection was aborted by the software in your host machine." ||
		msg == "wsasend: An established connection was aborted by the software in your host machine." ||
		msg == "wsarecv: An existing connection was forcibly closed by the remote host." ||
		msg == "wsasend: An existing connection was forcibly closed by the remote host."
}

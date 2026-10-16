package proxy

import (
	"errors"
	"fmt"
	"net"
)

// ErrNonLoopbackAddress is returned when an address other than 127.0.0.1 is specified.
var ErrNonLoopbackAddress = errors.New("binding rejected: listener must be strictly bound to 127.0.0.1 for loopback safety")

// ListenLoopback creates a TCP listener bound strictly to 127.0.0.1:<port>.
// Any attempt to bind to 0.0.0.0, LAN addresses, or IPv6 ::1 will be rejected
// to prevent accidental exposure to external network interfaces.
func ListenLoopback(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address format %q: %w", addr, err)
	}

	if host != "127.0.0.1" {
		return nil, fmt.Errorf("%w (attempted: %s)", ErrNonLoopbackAddress, host)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener on %s: %w", addr, err)
	}

	return ln, nil
}

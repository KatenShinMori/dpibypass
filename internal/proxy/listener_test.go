package proxy

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestListenLoopbackSuccess(t *testing.T) {
	ln, err := ListenLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected successful loopback bind, got: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("expected listener on 127.0.0.1, got %s", addr)
	}

	// Verify local connection to the listener works
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial loopback listener: %v", err)
	}
	defer conn.Close()

	clientConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to accept connection: %v", err)
	}
	defer clientConn.Close()
}

func TestListenLoopbackRejection(t *testing.T) {
	rejectAddrs := []string{
		"0.0.0.0:1080",
		"[::1]:1080",
		"192.168.1.50:1080",
		"10.0.0.2:1080",
		"localhost:1080",
	}

	for _, addr := range rejectAddrs {
		ln, err := ListenLoopback(addr)
		if err == nil {
			ln.Close()
			t.Errorf("expected rejection for address %q, but listener was created", addr)
		}
		if !errors.Is(err, ErrNonLoopbackAddress) && !strings.Contains(err.Error(), "rejected") {
			t.Errorf("expected loopback rejection error for %q, got: %v", addr, err)
		}
	}
}

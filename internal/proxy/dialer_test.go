package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockResolver struct {
	lookupFunc func(ctx context.Context, host string) ([]net.IP, error)
}

func (m *mockResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupFunc != nil {
		return m.lookupFunc(ctx, host)
	}
	return nil, errors.New("lookup not implemented")
}

func TestResolvingDialerIPLiteralBypass(t *testing.T) {
	resolverCalled := false
	res := &mockResolver{
		lookupFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			resolverCalled = true
			return nil, errors.New("resolver should not be called for IP literal")
		},
	}

	clientConn, srvConn := net.Pipe()
	defer clientConn.Close()
	defer srvConn.Close()

	dialedAddr := ""
	base := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedAddr = address
			return clientConn, nil
		},
	}

	d := NewResolvingDialer(base, res, 1*time.Second)

	conn, err := d.DialContext(context.Background(), "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn, got nil")
	}
	if resolverCalled {
		t.Error("resolver was unexpectedly called for IP literal destination")
	}
	if dialedAddr != "1.2.3.4:80" {
		t.Errorf("expected dialedAddr 1.2.3.4:80, got %s", dialedAddr)
	}
}

func TestResolvingDialerDomainSuccess(t *testing.T) {
	res := &mockResolver{
		lookupFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			if host != "example.com" {
				t.Errorf("expected host example.com, got %s", host)
			}
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
	}

	clientConn, srvConn := net.Pipe()
	defer clientConn.Close()
	defer srvConn.Close()

	dialedAddr := ""
	base := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedAddr = address
			return clientConn, nil
		},
	}

	d := NewResolvingDialer(base, res, 1*time.Second)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn, got nil")
	}
	if dialedAddr != "93.184.216.34:443" {
		t.Errorf("expected dialedAddr 93.184.216.34:443, got %s", dialedAddr)
	}
}

func TestResolvingDialerDualStackFallback(t *testing.T) {
	res := &mockResolver{
		lookupFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{
				net.ParseIP("2001:db8::1"),   // First: will fail
				net.ParseIP("93.184.216.34"), // Second: will succeed
			}, nil
		},
	}

	clientConn, srvConn := net.Pipe()
	defer clientConn.Close()
	defer srvConn.Close()

	var attempts []string
	base := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			if address == "[2001:db8::1]:443" {
				return nil, errors.New("connection refused")
			}
			return clientConn, nil
		},
	}

	d := NewResolvingDialer(base, res, 1*time.Second)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn, got nil")
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d: %v", len(attempts), attempts)
	}
	if attempts[0] != "[2001:db8::1]:443" || attempts[1] != "93.184.216.34:443" {
		t.Errorf("unexpected attempt order: %v", attempts)
	}
}

func TestResolvingDialerResolverError(t *testing.T) {
	res := &mockResolver{
		lookupFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, errors.New("NXDOMAIN")
		},
	}

	baseCalled := false
	base := &mockDialer{
		dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			baseCalled = true
			return nil, nil
		},
	}

	d := NewResolvingDialer(base, res, 1*time.Second)

	_, err := d.DialContext(context.Background(), "tcp", "nx.example.com:80")
	if err == nil {
		t.Fatal("expected error when resolver fails, got nil")
	}
	if baseCalled {
		t.Error("base dialer should not be called when resolver fails")
	}
}

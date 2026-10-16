package dnsdoh

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCachePositive(t *testing.T) {
	c := NewCache(10)
	now := time.Now()
	ips := []net.IP{net.ParseIP("1.2.3.4")}

	c.PutPositive("example.com", TypeA, ips, 60*time.Second, now)

	gotIPs, err, found := c.Get("example.com", TypeA, now.Add(10*time.Second))
	if !found {
		t.Fatal("expected cached entry to be found")
	}
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(gotIPs) != 1 || !gotIPs[0].Equal(ips[0]) {
		t.Fatalf("expected %v, got %v", ips, gotIPs)
	}

	// Verify expiration
	_, _, foundExpired := c.Get("example.com", TypeA, now.Add(61*time.Second))
	if foundExpired {
		t.Fatal("expected entry to be expired")
	}
}

func TestCacheTTLZeroNotCached(t *testing.T) {
	c := NewCache(10)
	now := time.Now()
	ips := []net.IP{net.ParseIP("1.2.3.4")}

	// Put with TTL 0
	c.PutPositive("example.com", TypeA, ips, 0, now)

	_, _, found := c.Get("example.com", TypeA, now)
	if found {
		t.Fatal("entry with TTL 0 should not be cached")
	}
}

func TestCacheNegativeSOA(t *testing.T) {
	c := NewCache(10)
	now := time.Now()

	// Put valid negative entry (e.g. NXDOMAIN with SOA negative TTL)
	c.PutNegative("missing.example.com", TypeA, ErrNXDomain, 300*time.Second, now)

	gotIPs, err, found := c.Get("missing.example.com", TypeA, now.Add(10*time.Second))
	if !found {
		t.Fatal("expected negative entry to be found")
	}
	if len(gotIPs) != 0 {
		t.Fatalf("expected 0 IPs, got %d", len(gotIPs))
	}
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}

	// Negative with zero TTL must not be cached
	c.PutNegative("zero.example.com", TypeA, ErrNXDomain, 0, now)
	_, _, foundZero := c.Get("zero.example.com", TypeA, now)
	if foundZero {
		t.Fatal("negative entry with TTL 0 should not be cached")
	}
}

func TestCacheFailureClampingRFC9520(t *testing.T) {
	c := NewCache(10)
	now := time.Now()

	// Test lower clamp: 500ms -> clamped to 1s minimum per RFC 9520
	c.PutFailure("servfail.example.com", TypeA, ErrServFail, 500*time.Millisecond, now)
	entryKey := cacheKey{Name: "servfail.example.com", QType: TypeA}
	entry := c.entries[entryKey]
	if entry == nil {
		t.Fatal("expected failure entry to be cached")
	}
	expectedMinExpiry := now.Add(1 * time.Second)
	if entry.ExpiresAt.Before(expectedMinExpiry) {
		t.Errorf("expected failure expiry >= %v, got %v", expectedMinExpiry, entry.ExpiresAt)
	}

	// Test upper clamp: 600s -> clamped to 300s (5 minutes) maximum per RFC 9520
	c.PutFailure("overflow.example.com", TypeA, ErrServFail, 600*time.Second, now)
	entryKey2 := cacheKey{Name: "overflow.example.com", QType: TypeA}
	entry2 := c.entries[entryKey2]
	expectedMaxExpiry := now.Add(300 * time.Second)
	if entry2.ExpiresAt.After(expectedMaxExpiry) {
		t.Errorf("expected failure expiry <= %v, got %v", expectedMaxExpiry, entry2.ExpiresAt)
	}
}

func TestCacheCapacityEviction(t *testing.T) {
	c := NewCache(3)
	now := time.Now()

	c.PutPositive("domain1.com", TypeA, []net.IP{net.ParseIP("1.1.1.1")}, 100*time.Second, now)
	c.PutPositive("domain2.com", TypeA, []net.IP{net.ParseIP("2.2.2.2")}, 100*time.Second, now.Add(1*time.Second))
	c.PutPositive("domain3.com", TypeA, []net.IP{net.ParseIP("3.3.3.3")}, 100*time.Second, now.Add(2*time.Second))

	if c.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", c.Len())
	}

	// Insert 4th entry; oldest (domain1.com) should be evicted
	c.PutPositive("domain4.com", TypeA, []net.IP{net.ParseIP("4.4.4.4")}, 100*time.Second, now.Add(3*time.Second))

	if c.Len() > 3 {
		t.Fatalf("expected cache size bounded to <= 3, got %d", c.Len())
	}
	_, _, found1 := c.Get("domain1.com", TypeA, now)
	if found1 {
		t.Fatal("expected oldest domain1.com to have been evicted")
	}
	_, _, found4 := c.Get("domain4.com", TypeA, now)
	if !found4 {
		t.Fatal("expected newly inserted domain4.com to be present")
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := NewCache(50)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			now := time.Now()
			for j := 0; j < 50; j++ {
				c.PutPositive("concurrent.com", TypeA, []net.IP{net.ParseIP("1.1.1.1")}, 10*time.Second, now)
				c.Get("concurrent.com", TypeA, now)
				c.PutNegative("nx.com", TypeA, ErrNXDomain, 10*time.Second, now)
				c.Get("nx.com", TypeA, now)
				c.PutFailure("fail.com", TypeA, ErrServFail, 5*time.Second, now)
				c.Get("fail.com", TypeA, now)
			}
		}(i)
	}

	wg.Wait()
}

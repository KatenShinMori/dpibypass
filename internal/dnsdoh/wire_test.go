package dnsdoh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildQuery(t *testing.T) {
	t.Run("valid A query", func(t *testing.T) {
		q, err := BuildQuery("example.com", TypeA, 0x1234)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(q) < 12 {
			t.Fatalf("query too short: %d bytes", len(q))
		}
		id := binary.BigEndian.Uint16(q[0:2])
		if id != 0x1234 {
			t.Errorf("expected ID 0x1234, got 0x%04x", id)
		}
		flags := binary.BigEndian.Uint16(q[2:4])
		if flags != 0x0100 { // RD=1
			t.Errorf("expected flags 0x0100, got 0x%04x", flags)
		}
	})

	t.Run("valid AAAA query with trailing dot", func(t *testing.T) {
		q, err := BuildQuery("example.com.", TypeAAAA, 0x5678)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		id := binary.BigEndian.Uint16(q[0:2])
		if id != 0x5678 {
			t.Errorf("expected ID 0x5678, got 0x%04x", id)
		}
	})

	t.Run("empty domain rejected", func(t *testing.T) {
		if _, err := BuildQuery("", TypeA, 1); err == nil {
			t.Fatal("expected error for empty domain")
		}
	})

	t.Run("overlong domain rejected", func(t *testing.T) {
		overlong := strings.Repeat("a.", 130) // > 253 chars
		if _, err := BuildQuery(overlong, TypeA, 1); err == nil {
			t.Fatal("expected error for overlong domain")
		}
	})

	t.Run("overlong label rejected", func(t *testing.T) {
		badLabel := strings.Repeat("a", 64) + ".com"
		if _, err := BuildQuery(badLabel, TypeA, 1); err == nil {
			t.Fatal("expected error for label > 63 chars")
		}
	})
}

// helper to construct a wire-format DNS response with Question section
func makeBaseResponse(id uint16, flags uint16, domain string, qtype uint16) *bytes.Buffer {
	buf := new(bytes.Buffer)
	// Header: ID(2), Flags(2), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	_ = binary.Write(buf, binary.BigEndian, id)
	_ = binary.Write(buf, binary.BigEndian, flags)
	_ = binary.Write(buf, binary.BigEndian, uint16(1)) // QDCOUNT
	_ = binary.Write(buf, binary.BigEndian, uint16(0)) // ANCOUNT (caller can overwrite or append)
	_ = binary.Write(buf, binary.BigEndian, uint16(0)) // NSCOUNT
	_ = binary.Write(buf, binary.BigEndian, uint16(0)) // ARCOUNT

	// Question section
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, l := range labels {
		buf.WriteByte(byte(len(l)))
		buf.WriteString(l)
	}
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, qtype)
	_ = binary.Write(buf, binary.BigEndian, ClassINET)
	return buf
}

func TestParseResponseSuccessA(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x1000, 0x8180, domain, TypeA) // QR=1, RD=1, RA=1, NoError

	// Overwrite ANCOUNT = 1 in header (bytes 6:8)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1)

	// Append Answer RR: Pointer to question name (0xC00C), TypeA, ClassIN, TTL=300, RDLENGTH=4, IP=93.184.216.34
	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C}) // Pointer to offset 12
	_ = binary.Write(ansBuf, binary.BigEndian, TypeA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(300)) // TTL = 300s
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))   // RDLENGTH = 4
	ansBuf.Write([]byte{93, 184, 216, 34})

	msg := append(data, ansBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x1000, domain, TypeA)
	if err != nil {
		t.Fatalf("unexpected error parsing valid A response: %v", err)
	}
	if len(resp.IPs) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(resp.IPs))
	}
	expectedIP := net.IPv4(93, 184, 216, 34)
	if !resp.IPs[0].Equal(expectedIP) {
		t.Errorf("expected IP %s, got %s", expectedIP, resp.IPs[0])
	}
	if resp.TTL != 300*time.Second {
		t.Errorf("expected TTL 300s, got %v", resp.TTL)
	}
}

func TestParseResponseSuccessAAAA(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x2000, 0x8180, domain, TypeAAAA)

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1) // ANCOUNT = 1

	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(ansBuf, binary.BigEndian, TypeAAAA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(60)) // TTL = 60s
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(16)) // RDLENGTH = 16
	ipv6Bytes := net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")
	ansBuf.Write(ipv6Bytes)

	msg := append(data, ansBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x2000, domain, TypeAAAA)
	if err != nil {
		t.Fatalf("unexpected error parsing valid AAAA response: %v", err)
	}
	if len(resp.IPs) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(resp.IPs))
	}
	if !resp.IPs[0].Equal(ipv6Bytes) {
		t.Errorf("expected IP %s, got %s", ipv6Bytes, resp.IPs[0])
	}
	if resp.TTL != 60*time.Second {
		t.Errorf("expected TTL 60s, got %v", resp.TTL)
	}
}

func TestParseResponseTTLZero(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x3000, 0x8180, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1)

	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(ansBuf, binary.BigEndian, TypeA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(0)) // TTL = 0
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
	ansBuf.Write([]byte{1, 2, 3, 4})

	msg := append(data, ansBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x3000, domain, TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.TTL != 0 {
		t.Errorf("expected TTL 0, got %v", resp.TTL)
	}
}

func TestParseResponseTTLUpperCap(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x4000, 0x8180, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1)

	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(ansBuf, binary.BigEndian, TypeA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(500000)) // TTL = 500,000s (> 86400s)
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
	ansBuf.Write([]byte{1, 2, 3, 4})

	msg := append(data, ansBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x4000, domain, TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.TTL != 86400*time.Second {
		t.Errorf("expected capped TTL 86400s, got %v", resp.TTL)
	}
}

func TestParseResponseIDAndQuestionMismatch(t *testing.T) {
	t.Run("ID mismatch", func(t *testing.T) {
		buf := makeBaseResponse(0x1111, 0x8180, "example.com", TypeA)
		if _, err := ParseResponse(buf.Bytes(), 0x2222, "example.com", TypeA); !errors.Is(err, ErrIDMismatch) {
			t.Fatalf("expected ErrIDMismatch, got %v", err)
		}
	})

	t.Run("Question mismatch", func(t *testing.T) {
		buf := makeBaseResponse(0x1111, 0x8180, "other.com", TypeA)
		if _, err := ParseResponse(buf.Bytes(), 0x1111, "example.com", TypeA); !errors.Is(err, ErrQuestionMismatch) {
			t.Fatalf("expected ErrQuestionMismatch, got %v", err)
		}
	})
}

func TestParseResponseAnswerOwnershipValidation(t *testing.T) {
	// Query is for "example.com", but answer RR is for "attacker.com"
	domain := "example.com"
	buf := makeBaseResponse(0x5000, 0x8180, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1) // ANCOUNT = 1

	ansBuf := new(bytes.Buffer)
	// Write "attacker.com" label
	ansBuf.WriteByte(8)
	ansBuf.WriteString("attacker")
	ansBuf.WriteByte(3)
	ansBuf.WriteString("com")
	ansBuf.WriteByte(0)
	_ = binary.Write(ansBuf, binary.BigEndian, TypeA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(300))
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
	ansBuf.Write([]byte{6, 6, 6, 6})

	msg := append(data, ansBuf.Bytes()...)

	// Should reject unrelated answer record and return ErrNoData (or no matching addresses)
	resp, err := ParseResponse(msg, 0x5000, domain, TypeA)
	if !errors.Is(err, ErrNoData) {
		t.Fatalf("expected ErrNoData due to ownership mismatch, got resp: %+v, err: %v", resp, err)
	}
}

func TestParseResponseCNAMEChain(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x6000, 0x8180, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 2) // ANCOUNT = 2

	// Answer 1: example.com CNAME alias.example.com (TTL=100)
	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C}) // Pointer to example.com
	_ = binary.Write(ansBuf, binary.BigEndian, TypeCNAME)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(100))
	// CNAME target: alias.example.com
	targetBuf := new(bytes.Buffer)
	targetBuf.WriteByte(5)
	targetBuf.WriteString("alias")
	targetBuf.Write([]byte{0xC0, 0x0C}) // Pointer to example.com
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(targetBuf.Len()))
	ansBuf.Write(targetBuf.Bytes())

	// Answer 2: alias.example.com A 93.184.216.34 (TTL=300)
	ansBuf.WriteByte(5)
	ansBuf.WriteString("alias")
	ansBuf.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(ansBuf, binary.BigEndian, TypeA)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(300))
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(4))
	ansBuf.Write([]byte{93, 184, 216, 34})

	msg := append(data, ansBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x6000, domain, TypeA)
	if err != nil {
		t.Fatalf("unexpected error parsing CNAME chain: %v", err)
	}
	if len(resp.IPs) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(resp.IPs))
	}
	// Effective TTL must be min(100, 300) = 100s
	if resp.TTL != 100*time.Second {
		t.Errorf("expected effective TTL 100s, got %v", resp.TTL)
	}
}

func TestParseResponseCNAMELoop(t *testing.T) {
	domain := "example.com"
	buf := makeBaseResponse(0x7000, 0x8180, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[6:8], 1)

	// Answer: example.com CNAME example.com
	ansBuf := new(bytes.Buffer)
	ansBuf.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(ansBuf, binary.BigEndian, TypeCNAME)
	_ = binary.Write(ansBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(ansBuf, binary.BigEndian, uint32(60))
	_ = binary.Write(ansBuf, binary.BigEndian, uint16(2))
	ansBuf.Write([]byte{0xC0, 0x0C}) // Self loop pointer

	msg := append(data, ansBuf.Bytes()...)

	if _, err := ParseResponse(msg, 0x7000, domain, TypeA); !errors.Is(err, ErrCNAMELoop) {
		t.Fatalf("expected ErrCNAMELoop, got %v", err)
	}
}

func TestParseResponseCompressionPointerEdgeCases(t *testing.T) {
	domain := "example.com"

	t.Run("pointer loop", func(t *testing.T) {
		buf := makeBaseResponse(0x8000, 0x8180, domain, TypeA)
		data := buf.Bytes()
		binary.BigEndian.PutUint16(data[6:8], 1)

		// Create a pointer loop at end of message: offset points to itself
		ansOffset := len(data)
		ptrBytes := []byte{0xC0, byte(ansOffset)}
		msg := append(data, ptrBytes...)

		if _, err := ParseResponse(msg, 0x8000, domain, TypeA); !errors.Is(err, ErrPointerLoop) && !errors.Is(err, ErrMalformedMessage) {
			t.Fatalf("expected ErrPointerLoop, got %v", err)
		}
	})

	t.Run("out of bounds pointer", func(t *testing.T) {
		buf := makeBaseResponse(0x8001, 0x8180, domain, TypeA)
		data := buf.Bytes()
		binary.BigEndian.PutUint16(data[6:8], 1)

		// Pointer to 0x3FFF (way beyond message length)
		badPtr := []byte{0xC0, 0xFF}
		msg := append(data, badPtr...)

		if _, err := ParseResponse(msg, 0x8001, domain, TypeA); !errors.Is(err, ErrInvalidPointer) && !errors.Is(err, ErrMalformedMessage) {
			t.Fatalf("expected ErrInvalidPointer, got %v", err)
		}
	})
}

func TestParseResponseNXDomainWithSOA(t *testing.T) {
	domain := "nonexistent.example.com"
	// RCODE = 3 (NXDOMAIN) -> flags = 0x8183
	buf := makeBaseResponse(0x9000, 0x8183, domain, TypeA)
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[8:10], 1) // NSCOUNT = 1

	// Authority section: SOA record with TTL=1800, MINIMUM=900
	soaBuf := new(bytes.Buffer)
	soaBuf.WriteByte(7)
	soaBuf.WriteString("example")
	soaBuf.WriteByte(3)
	soaBuf.WriteString("com")
	soaBuf.WriteByte(0)
	_ = binary.Write(soaBuf, binary.BigEndian, TypeSOA)
	_ = binary.Write(soaBuf, binary.BigEndian, ClassINET)
	_ = binary.Write(soaBuf, binary.BigEndian, uint32(1800)) // SOA TTL = 1800s

	// SOA RDATA: MNAME, RNAME, SERIAL(4), REFRESH(4), RETRY(4), EXPIRE(4), MINIMUM(4)
	rdata := new(bytes.Buffer)
	rdata.Write([]byte{2, 'n', 's', 0})                     // MNAME = ns
	rdata.Write([]byte{4, 'h', 'o', 's', 't', 0})           // RNAME = host
	_ = binary.Write(rdata, binary.BigEndian, uint32(1))    // Serial
	_ = binary.Write(rdata, binary.BigEndian, uint32(7200)) // Refresh
	_ = binary.Write(rdata, binary.BigEndian, uint32(3600)) // Retry
	_ = binary.Write(rdata, binary.BigEndian, uint32(1200)) // Expire
	_ = binary.Write(rdata, binary.BigEndian, uint32(900))  // Minimum = 900s

	_ = binary.Write(soaBuf, binary.BigEndian, uint16(rdata.Len()))
	soaBuf.Write(rdata.Bytes())

	msg := append(data, soaBuf.Bytes()...)

	resp, err := ParseResponse(msg, 0x9000, domain, TypeA)
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("expected ErrNXDomain, got %v", err)
	}
	if !resp.HasSOA {
		t.Fatal("expected HasSOA to be true")
	}
	// RFC 2308: Negative TTL = min(SOA.TTL (1800), SOA.MINIMUM (900)) = 900s
	if resp.NegativeTTL != 900*time.Second {
		t.Errorf("expected NegativeTTL 900s, got %v", resp.NegativeTTL)
	}
}

func TestParseResponseMalformed(t *testing.T) {
	t.Run("truncated header < 12 bytes", func(t *testing.T) {
		if _, err := ParseResponse([]byte{0, 1, 2}, 1, "test.com", TypeA); !errors.Is(err, ErrMalformedMessage) {
			t.Fatalf("expected ErrMalformedMessage, got %v", err)
		}
	})

	t.Run("not a response QR=0", func(t *testing.T) {
		msg := make([]byte, 12)
		if _, err := ParseResponse(msg, 0, "test.com", TypeA); !errors.Is(err, ErrMalformedMessage) {
			t.Fatalf("expected ErrMalformedMessage for QR=0, got %v", err)
		}
	})
}

func TestParseDNSQuery(t *testing.T) {
	t.Run("valid A query", func(t *testing.T) {
		queryWire, err := BuildQuery("updates.discord.com", TypeA, 0x1234)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		if q.ID != 0x1234 {
			t.Errorf("expected ID 0x1234, got 0x%x", q.ID)
		}
		if q.Question.Name != "updates.discord.com" {
			t.Errorf("expected updates.discord.com, got %q", q.Question.Name)
		}
		if q.Question.Type != TypeA {
			t.Errorf("expected TypeA (1), got %d", q.Question.Type)
		}
		if q.Question.Class != ClassINET {
			t.Errorf("expected ClassINET (1), got %d", q.Question.Class)
		}
		if len(q.RawQuestion) == 0 {
			t.Error("expected non-empty RawQuestion")
		}
	})

	t.Run("valid AAAA query", func(t *testing.T) {
		queryWire, err := BuildQuery("www.roblox.com", TypeAAAA, 0xABCD)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		if q.ID != 0xABCD {
			t.Errorf("expected ID 0xABCD, got 0x%x", q.ID)
		}
		if q.Question.Name != "www.roblox.com" {
			t.Errorf("expected www.roblox.com, got %q", q.Question.Name)
		}
		if q.Question.Type != TypeAAAA {
			t.Errorf("expected TypeAAAA (28), got %d", q.Question.Type)
		}
	})

	t.Run("malformed query header < 12 bytes", func(t *testing.T) {
		_, err := ParseDNSQuery([]byte{0x01, 0x02})
		if !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("expected ErrMalformedMessage, got %v", err)
		}
	})

	t.Run("QR bit is 1 (response not query)", func(t *testing.T) {
		msg := make([]byte, 12)
		msg[2] = 0x80 // QR = 1
		_, err := ParseDNSQuery(msg)
		if !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("expected ErrMalformedMessage for QR=1, got %v", err)
		}
	})

	t.Run("QDCount is 0", func(t *testing.T) {
		msg := make([]byte, 12)
		_, err := ParseDNSQuery(msg)
		if !errors.Is(err, ErrQuestionMismatch) {
			t.Errorf("expected ErrQuestionMismatch for QDCount=0, got %v", err)
		}
	})

	t.Run("query with EDNS0 OPT record in additional section", func(t *testing.T) {
		// Real modern Windows DNS queries include an EDNS0 OPT RR (RFC 6891) in Additional section
		baseQuery, err := BuildQuery("updates.discord.com", TypeA, 0x1234)
		if err != nil {
			t.Fatalf("BuildQuery: %v", err)
		}

		// Set ARCOUNT = 1 in header (bytes 10..12)
		binary.BigEndian.PutUint16(baseQuery[10:12], 1)

		// Append EDNS0 OPT RR (RFC 6891): Name 0x00, Type 41 (OPT), UDP Payload Size 1232, RCODE/Flags 0, RDLEN 0
		optRR := []byte{
			0x00,       // Root domain
			0x00, 0x29, // Type OPT (41)
			0x04, 0xD0, // UDP payload size (1232)
			0x00, 0x00, 0x00, 0x00, // Extended RCODE and flags
			0x00, 0x00, // RDLEN = 0
		}
		ednsQuery := append(baseQuery, optRR...)

		q, err := ParseDNSQuery(ednsQuery)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed on EDNS0 query: %v", err)
		}
		if q.Question.Name != "updates.discord.com" {
			t.Errorf("expected updates.discord.com, got %q", q.Question.Name)
		}
		if q.Question.Type != TypeA {
			t.Errorf("expected TypeA, got %d", q.Question.Type)
		}

		// Verify BuildDNSResponse produces valid response
		respWire, err := BuildDNSResponse(q, []net.IP{net.ParseIP("162.159.130.233")}, 60*time.Second)
		if err != nil {
			t.Fatalf("BuildDNSResponse on EDNS0 query failed: %v", err)
		}
		parsed, err := ParseResponse(respWire, 0x1234, "updates.discord.com", TypeA)
		if err != nil {
			t.Fatalf("ParseResponse failed on response: %v", err)
		}
		if len(parsed.IPs) != 1 {
			t.Fatalf("expected 1 IP, got %d", len(parsed.IPs))
		}
	})

	t.Run("compression pointer in question section rejected", func(t *testing.T) {
		msg := make([]byte, 16)
		// Header with QDCount = 1
		binary.BigEndian.PutUint16(msg[4:6], 1)
		// Question at offset 12 with 0xC000
		msg[12] = 0xC0
		msg[13] = 0x00
		_, err := ParseDNSQuery(msg)
		if !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("expected ErrMalformedMessage for compressed question name, got %v", err)
		}
	})

	t.Run("query truncated in question section", func(t *testing.T) {
		msg := make([]byte, 14)
		binary.BigEndian.PutUint16(msg[4:6], 1)
		msg[12] = 0x01
		msg[13] = 'a'
		// Missing terminating null byte and QTYPE/QCLASS
		_, err := ParseDNSQuery(msg)
		if !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("expected ErrMalformedMessage for truncated question, got %v", err)
		}
	})
}

func TestBuildDNSResponse(t *testing.T) {
	t.Run("synthesize A response and parse back", func(t *testing.T) {
		queryWire, err := BuildQuery("updates.discord.com", TypeA, 0x4321)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		ips := []net.IP{
			net.ParseIP("162.159.130.233"),
			net.ParseIP("162.159.133.233"),
		}

		respWire, err := BuildDNSResponse(q, ips, 120*time.Second)
		if err != nil {
			t.Fatalf("BuildDNSResponse failed: %v", err)
		}

		// Verify round-trip parsing with ParseResponse
		parsed, err := ParseResponse(respWire, 0x4321, "updates.discord.com", TypeA)
		if err != nil {
			t.Fatalf("ParseResponse failed on synthesized wire response: %v", err)
		}

		if len(parsed.IPs) != 2 {
			t.Fatalf("expected 2 IPs, got %d", len(parsed.IPs))
		}
		if !parsed.IPs[0].Equal(ips[0]) || !parsed.IPs[1].Equal(ips[1]) {
			t.Errorf("IP mismatch: got %v, expected %v", parsed.IPs, ips)
		}
		if parsed.TTL != 120*time.Second {
			t.Errorf("expected TTL 120s, got %v", parsed.TTL)
		}
	})

	t.Run("synthesize AAAA response and parse back", func(t *testing.T) {
		queryWire, err := BuildQuery("www.roblox.com", TypeAAAA, 0x9999)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		ips := []net.IP{
			net.ParseIP("2606:4700:20::681a:64a"),
		}

		respWire, err := BuildDNSResponse(q, ips, 300*time.Second)
		if err != nil {
			t.Fatalf("BuildDNSResponse failed: %v", err)
		}

		parsed, err := ParseResponse(respWire, 0x9999, "www.roblox.com", TypeAAAA)
		if err != nil {
			t.Fatalf("ParseResponse failed on synthesized AAAA response: %v", err)
		}

		if len(parsed.IPs) != 1 || !parsed.IPs[0].Equal(ips[0]) {
			t.Errorf("IP mismatch: got %v, expected %v", parsed.IPs, ips)
		}
	})

	t.Run("synthesize clean NODATA response (empty IPs)", func(t *testing.T) {
		queryWire, err := BuildQuery("ipv4only.example.com", TypeAAAA, 0x5555)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		respWire, err := BuildDNSResponse(q, nil, 60*time.Second)
		if err != nil {
			t.Fatalf("BuildDNSResponse failed: %v", err)
		}

		// Header checks: QR=1, RCODE=0, QDCOUNT=1, ANCOUNT=0
		flags := binary.BigEndian.Uint16(respWire[2:4])
		rcode := byte(flags & 0x0F)
		anCount := binary.BigEndian.Uint16(respWire[6:8])

		if rcode != 0 {
			t.Errorf("expected RCODE 0 for NODATA, got %d", rcode)
		}
		if anCount != 0 {
			t.Errorf("expected ANCOUNT 0 for NODATA, got %d", anCount)
		}

		// ParseResponse on NODATA returns ErrNoData
		_, err = ParseResponse(respWire, 0x5555, "ipv4only.example.com", TypeAAAA)
		if !errors.Is(err, ErrNoData) {
			t.Errorf("expected ErrNoData, got %v", err)
		}
	})
}

func TestBuildDNSServFailResponse(t *testing.T) {
	t.Run("nil query returns error", func(t *testing.T) {
		_, err := BuildDNSServFailResponse(nil)
		if err == nil {
			t.Fatal("expected error for nil query, got nil")
		}
	})

	t.Run("synthesize valid SERVFAIL wire format", func(t *testing.T) {
		queryWire, err := BuildQuery("blocked.example.com", TypeA, 0x7777)
		if err != nil {
			t.Fatalf("BuildQuery failed: %v", err)
		}

		q, err := ParseDNSQuery(queryWire)
		if err != nil {
			t.Fatalf("ParseDNSQuery failed: %v", err)
		}

		sfWire, err := BuildDNSServFailResponse(q)
		if err != nil {
			t.Fatalf("BuildDNSServFailResponse failed: %v", err)
		}

		if len(sfWire) != len(queryWire) {
			t.Fatalf("expected SERVFAIL length %d, got %d", len(queryWire), len(sfWire))
		}

		// ID check
		id := binary.BigEndian.Uint16(sfWire[0:2])
		if id != 0x7777 {
			t.Errorf("expected ID 0x7777, got 0x%04x", id)
		}

		// Flags: QR=1, RCODE=2 (ServFail), RA=1, RD preserved
		flags := binary.BigEndian.Uint16(sfWire[2:4])
		qr := (flags >> 15) & 1
		ra := (flags >> 7) & 1
		rd := (flags >> 8) & 1
		rcode := byte(flags & 0x0F)

		if qr != 1 {
			t.Errorf("expected QR=1, got %d", qr)
		}
		if ra != 1 {
			t.Errorf("expected RA=1, got %d", ra)
		}
		if rd != 1 { // BuildQuery sets RD=1
			t.Errorf("expected RD=1, got %d", rd)
		}
		if rcode != RCodeServFail {
			t.Errorf("expected RCODE %d (ServFail), got %d", RCodeServFail, rcode)
		}

		// Counts: QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
		qdCount := binary.BigEndian.Uint16(sfWire[4:6])
		anCount := binary.BigEndian.Uint16(sfWire[6:8])
		nsCount := binary.BigEndian.Uint16(sfWire[8:10])
		arCount := binary.BigEndian.Uint16(sfWire[10:12])

		if qdCount != 1 || anCount != 0 || nsCount != 0 || arCount != 0 {
			t.Errorf("unexpected counts: qd=%d, an=%d, ns=%d, ar=%d", qdCount, anCount, nsCount, arCount)
		}

		// Question verbatim check
		if !bytes.Equal(sfWire[12:], queryWire[12:]) {
			t.Errorf("question section mismatch between query and SERVFAIL response")
		}

		// ParseResponse should recognize SERVFAIL
		_, err = ParseResponse(sfWire, 0x7777, "blocked.example.com", TypeA)
		if !errors.Is(err, ErrServFail) {
			t.Errorf("expected ErrServFail from ParseResponse, got %v", err)
		}
	})
}

package dnsdoh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNS protocol constants (RFC 1035, RFC 3596, RFC 2308, RFC 9520).
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeAAAA  uint16 = 28
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65

	ClassINET uint16 = 1

	// RCODE status values
	RCodeNoError  byte = 0
	RCodeFormErr  byte = 1
	RCodeServFail byte = 2
	RCodeNXDomain byte = 3
	RCodeNotImp   byte = 4
	RCodeRefused  byte = 5

	// Maximum limits for bounded wire parsing
	MaxDNSMessageBytes    = 65536 // 64 KB maximum message size
	MaxDomainNameLength   = 253   // RFC 1035 §2.3.4
	MaxLabelLength        = 63    // RFC 1035 §2.3.4
	MaxCompressionPointer = 8     // Maximum compression pointer depth to avoid loops
	MaxAnswerCount        = 64    // Maximum answers parsed to avoid unbounded iterations
	MaxCNAMEChainDepth    = 4     // Maximum CNAME alias chain hops
	MaxCachedTTLSeconds   = 86400 // Upper cap on cached TTL (24 hours)
)

// Error definitions for DNS response classification.
var (
	ErrNXDomain         = errors.New("dns: name error (NXDOMAIN)")
	ErrNoData           = errors.New("dns: no data for requested query type (NODATA)")
	ErrServFail         = errors.New("dns: server failure (SERVFAIL)")
	ErrFormErr          = errors.New("dns: format error (FormErr)")
	ErrRefused          = errors.New("dns: query refused (Refused)")
	ErrMessageTruncated = errors.New("dns: message truncated (TC bit set)")
	ErrPointerLoop      = errors.New("dns: compression pointer loop detected")
	ErrInvalidPointer   = errors.New("dns: invalid compression pointer offset")
	ErrMalformedMessage = errors.New("dns: malformed message wire format")
	ErrIDMismatch       = errors.New("dns: response ID does not match query ID")
	ErrQuestionMismatch = errors.New("dns: response question does not match query")
	ErrCNAMELoop        = errors.New("dns: CNAME alias loop detected")
	ErrCNAMEDepthExceed = errors.New("dns: CNAME alias chain exceeded maximum depth")
	ErrAnswerNotOwned   = errors.New("dns: answer record does not match queried name or alias")
)

// ResourceRecord represents a parsed DNS resource record header and payload boundaries.
type ResourceRecord struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	Data        []byte
	RDataOffset int
}

// SOARecord represents a parsed SOA record for negative caching calculation (RFC 2308).
type SOARecord struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32 // Negative caching TTL per RFC 2308 §4
	TTL     uint32
}

// Response contains validated parsing results from a DNS wire response.
type Response struct {
	ID          uint16
	RCode       byte
	IsResponse  bool
	Truncated   bool
	IPs         []net.IP
	TTL         time.Duration // Effective positive TTL (minimum across chain, capped at 86400s)
	NegativeTTL time.Duration // Effective negative TTL derived from SOA (RFC 2308)
	HasSOA      bool
	SOA         SOARecord
}

// DNSQuestion represents a parsed question section in a DNS query.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSQuery represents a parsed DNS query wire payload.
type DNSQuery struct {
	ID          uint16
	Flags       uint16
	Question    DNSQuestion
	RawQuestion []byte // Raw question bytes (name + type + class) to copy into responses verbatim
}

// ParseDNSQuery validates and decodes a wire-format DNS query message (RFC 1035).
func ParseDNSQuery(msg []byte) (*DNSQuery, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("%w: query too short (%d bytes)", ErrMalformedMessage, len(msg))
	}
	if len(msg) > MaxDNSMessageBytes {
		return nil, fmt.Errorf("%w: query exceeds %d bytes", ErrMalformedMessage, MaxDNSMessageBytes)
	}

	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])

	qr := (flags >> 15) & 1
	if qr != 0 {
		return nil, fmt.Errorf("%w: message is a response (QR=1), expected query", ErrMalformedMessage)
	}
	opcode := (flags >> 11) & 0x0F
	if opcode != 0 {
		return nil, fmt.Errorf("%w: unsupported opcode %d in query", ErrMalformedMessage, opcode)
	}

	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount != 1 {
		return nil, fmt.Errorf("%w: expected 1 question, got %d", ErrQuestionMismatch, qdCount)
	}

	// In RFC 1035 §4.1.2, the Question section domain name is the first name in the message
	// and cannot be compressed (pointers can only point to preceding byte offsets).
	if msg[12]&0xC0 == 0xC0 {
		return nil, fmt.Errorf("%w: compression pointer not permitted in question name", ErrMalformedMessage)
	}

	qName, newOffset, err := parseDomainName(msg, 12, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: parse question name: %v", ErrMalformedMessage, err)
	}

	if newOffset+4 > len(msg) {
		return nil, fmt.Errorf("%w: truncated question section in query", ErrMalformedMessage)
	}

	qType := binary.BigEndian.Uint16(msg[newOffset : newOffset+2])
	qClass := binary.BigEndian.Uint16(msg[newOffset+2 : newOffset+4])
	rawQuestion := append([]byte(nil), msg[12:newOffset+4]...)

	return &DNSQuery{
		ID:    id,
		Flags: flags,
		Question: DNSQuestion{
			Name:  strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qName), ".")),
			Type:  qType,
			Class: qClass,
		},
		RawQuestion: rawQuestion,
	}, nil
}

// BuildDNSResponse synthesizes an RFC 1035 DNS response payload for the given query and resolved IP addresses.
// If ips is empty or contains no records matching query.Question.Type, it constructs a clean NODATA response (RCODE=0, ANCOUNT=0).
func BuildDNSResponse(query *DNSQuery, ips []net.IP, ttl time.Duration) ([]byte, error) {
	if query == nil {
		return nil, errors.New("cannot build DNS response for nil query")
	}

	buf := bytes.NewBuffer(make([]byte, 0, 512))

	// 1. Header (12 bytes)
	// ID: preserve query ID
	_ = binary.Write(buf, binary.BigEndian, query.ID)

	// Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=(from query), RA=1, Z=0, RCODE=0 (NoError)
	respFlags := uint16(0x8080) | (query.Flags & 0x0100)
	_ = binary.Write(buf, binary.BigEndian, respFlags)

	// Determine matching IPs and build answer RRs
	ttlSec := uint32(ttl.Seconds())
	if ttlSec == 0 {
		ttlSec = 60
	} else if ttlSec > MaxCachedTTLSeconds {
		ttlSec = MaxCachedTTLSeconds
	}

	var answersBuf bytes.Buffer
	var anCount uint16

	for _, ip := range ips {
		if query.Question.Type == TypeA {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			// Compression pointer 0xC00C pointing to Question Name at offset 12
			answersBuf.WriteByte(0xC0)
			answersBuf.WriteByte(0x0C)
			_ = binary.Write(&answersBuf, binary.BigEndian, TypeA)
			_ = binary.Write(&answersBuf, binary.BigEndian, ClassINET)
			_ = binary.Write(&answersBuf, binary.BigEndian, ttlSec)
			_ = binary.Write(&answersBuf, binary.BigEndian, uint16(4))
			answersBuf.Write(v4)
			anCount++
		} else if query.Question.Type == TypeAAAA {
			if ip.To4() != nil {
				continue
			}
			v6 := ip.To16()
			if v6 == nil {
				continue
			}
			// Compression pointer 0xC00C
			answersBuf.WriteByte(0xC0)
			answersBuf.WriteByte(0x0C)
			_ = binary.Write(&answersBuf, binary.BigEndian, TypeAAAA)
			_ = binary.Write(&answersBuf, binary.BigEndian, ClassINET)
			_ = binary.Write(&answersBuf, binary.BigEndian, ttlSec)
			_ = binary.Write(&answersBuf, binary.BigEndian, uint16(16))
			answersBuf.Write(v6)
			anCount++
		}
	}

	// QDCOUNT=1, ANCOUNT=anCount, NSCOUNT=0, ARCOUNT=0
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, anCount)
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// 2. Question section (copied verbatim from query)
	buf.Write(query.RawQuestion)

	// 3. Answer section
	if anCount > 0 {
		buf.Write(answersBuf.Bytes())
	}

	return buf.Bytes(), nil
}

// BuildDNSServFailResponse synthesizes an RFC 1035 SERVFAIL (RCODE=2) response for a query.
// It is used when DoH resolution fails for a target domain to avoid leaking queries to the ISP DNS.
func BuildDNSServFailResponse(query *DNSQuery) ([]byte, error) {
	if query == nil {
		return nil, errors.New("cannot build DNS response for nil query")
	}

	buf := bytes.NewBuffer(make([]byte, 0, 128))

	// 1. Header (12 bytes)
	// ID: preserve query ID
	_ = binary.Write(buf, binary.BigEndian, query.ID)

	// Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=(from query), RA=1, Z=0, RCODE=2 (ServFail)
	respFlags := uint16(0x8082) | (query.Flags & 0x0100)
	_ = binary.Write(buf, binary.BigEndian, respFlags)

	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// 2. Question section (copied verbatim from query)
	buf.Write(query.RawQuestion)

	return buf.Bytes(), nil
}

// BuildQuery encodes a standard DNS query wire format (RFC 1035) for A or AAAA records.
func BuildQuery(domain string, qtype uint16, id uint16) ([]byte, error) {
	norm := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if len(norm) == 0 || len(norm) > MaxDomainNameLength {
		return nil, fmt.Errorf("invalid domain name length %d (1..%d)", len(norm), MaxDomainNameLength)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 64))

	// 1. Header (12 bytes)
	// ID (16 bits)
	_ = binary.Write(buf, binary.BigEndian, id)
	// Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1 (0x0100)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0100))
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))

	// 2. Question section
	labels := strings.Split(norm, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return nil, fmt.Errorf("empty label in domain name %q", domain)
		}
		if len(label) > MaxLabelLength {
			return nil, fmt.Errorf("label %q exceeds maximum length %d", label, MaxLabelLength)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // Root null label

	// QTYPE and QCLASS (IN)
	_ = binary.Write(buf, binary.BigEndian, qtype)
	_ = binary.Write(buf, binary.BigEndian, ClassINET)

	return buf.Bytes(), nil
}

// ParseResponse validates and parses a DNS wire response against the expected query parameters.
func ParseResponse(msg []byte, expectedID uint16, expectedDomain string, expectedQType uint16) (*Response, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("%w: message too short (%d bytes)", ErrMalformedMessage, len(msg))
	}
	if len(msg) > MaxDNSMessageBytes {
		return nil, fmt.Errorf("%w: message exceeds %d bytes", ErrMalformedMessage, MaxDNSMessageBytes)
	}

	id := binary.BigEndian.Uint16(msg[0:2])
	if id != expectedID {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrIDMismatch, id, expectedID)
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	qr := (flags >> 15) & 1
	if qr != 1 {
		return nil, fmt.Errorf("%w: message is not a DNS response (QR=0)", ErrMalformedMessage)
	}
	opcode := (flags >> 11) & 0x0F
	if opcode != 0 {
		return nil, fmt.Errorf("%w: unsupported opcode %d", ErrMalformedMessage, opcode)
	}
	tc := (flags >> 9) & 1
	if tc == 1 {
		return nil, ErrMessageTruncated
	}

	rcode := byte(flags & 0x0F)
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	anCount := binary.BigEndian.Uint16(msg[6:8])
	nsCount := binary.BigEndian.Uint16(msg[8:10])

	if qdCount != 1 {
		return nil, fmt.Errorf("%w: expected 1 question, got %d", ErrQuestionMismatch, qdCount)
	}

	offset := 12

	// Parse Question section
	qName, newOffset, err := parseDomainName(msg, offset, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: parse question name: %v", ErrMalformedMessage, err)
	}
	offset = newOffset

	if offset+4 > len(msg) {
		return nil, fmt.Errorf("%w: truncated question section", ErrMalformedMessage)
	}
	qType := binary.BigEndian.Uint16(msg[offset : offset+2])
	qClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	offset += 4

	normExpected := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(expectedDomain), "."))
	normQName := strings.ToLower(strings.TrimSuffix(qName, "."))
	if normQName != normExpected || qType != expectedQType || qClass != ClassINET {
		return nil, fmt.Errorf("%w: question (%s, %d, %d) != expected (%s, %d, %d)",
			ErrQuestionMismatch, normQName, qType, qClass, normExpected, expectedQType, ClassINET)
	}

	resp := &Response{
		ID:         id,
		RCode:      rcode,
		IsResponse: true,
		Truncated:  false,
	}

	// Handle standard error RCODEs
	switch rcode {
	case RCodeNoError:
		// Process answers / authority below
	case RCodeNXDomain:
		// Check authority section for SOA negative caching per RFC 2308
		parseAuthoritySection(msg, offset, anCount, nsCount, resp)
		return resp, ErrNXDomain
	case RCodeServFail:
		return resp, ErrServFail
	case RCodeFormErr:
		return resp, ErrFormErr
	case RCodeRefused:
		return resp, ErrRefused
	default:
		return resp, fmt.Errorf("%w: rcode=%d", ErrMalformedMessage, rcode)
	}

	// If NoError but ANCOUNT == 0: this is NODATA
	if anCount == 0 {
		parseAuthoritySection(msg, offset, 0, nsCount, resp)
		return resp, ErrNoData
	}

	if anCount > MaxAnswerCount {
		anCount = MaxAnswerCount
	}

	// Parse Answer records
	var answers []ResourceRecord
	for i := 0; i < int(anCount); i++ {
		if offset >= len(msg) {
			break
		}
		name, newOff, err := parseDomainName(msg, offset, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: parse answer %d name: %v", ErrMalformedMessage, i, err)
		}
		offset = newOff

		if offset+10 > len(msg) {
			return nil, fmt.Errorf("%w: truncated answer %d header", ErrMalformedMessage, i)
		}

		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		rrTTL := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(msg[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(msg) {
			return nil, fmt.Errorf("%w: truncated answer %d rdata", ErrMalformedMessage, i)
		}

		rdataOffset := offset
		rdata := msg[offset : offset+int(rdLength)]
		offset += int(rdLength)

		if rrClass == ClassINET {
			answers = append(answers, ResourceRecord{
				Name:        strings.ToLower(strings.TrimSuffix(name, ".")),
				Type:        rrType,
				Class:       rrClass,
				TTL:         rrTTL,
				Data:        rdata,
				RDataOffset: rdataOffset,
			})
		}
	}

	// Bounded CNAME resolution and Answer Ownership Validation
	currentName := normExpected
	var cnameChain []string
	cnameChain = append(cnameChain, currentName)

	var validIPs []net.IP
	var minTTL uint32 = 0xFFFFFFFF
	hasMatchingRecord := false

	// Follow CNAME chain up to MaxCNAMEChainDepth
	for depth := 0; depth < MaxCNAMEChainDepth; depth++ {
		var nextCNAME string
		var cnameTTL uint32

		for _, ans := range answers {
			if ans.Name != currentName {
				continue // Skip answers not owned by the current name (Bailiwick / ownership check)
			}

			if ans.Type == TypeCNAME {
				targetName, _, err := parseDomainName(msg, ans.RDataOffset, 0)
				if err == nil {
					nextCNAME = strings.ToLower(strings.TrimSuffix(targetName, "."))
					cnameTTL = ans.TTL
				}
				break
			} else if ans.Type == expectedQType {
				if ans.Type == TypeA && len(ans.Data) == 4 {
					ip := net.IPv4(ans.Data[0], ans.Data[1], ans.Data[2], ans.Data[3])
					validIPs = append(validIPs, ip)
					hasMatchingRecord = true
					if ans.TTL < minTTL {
						minTTL = ans.TTL
					}
				} else if ans.Type == TypeAAAA && len(ans.Data) == 16 {
					ip := make(net.IP, 16)
					copy(ip, ans.Data)
					validIPs = append(validIPs, ip)
					hasMatchingRecord = true
					if ans.TTL < minTTL {
						minTTL = ans.TTL
					}
				}
			}
		}

		if hasMatchingRecord {
			// Found terminal address records for the active name in the chain
			break
		}

		if nextCNAME == "" {
			// No CNAME and no matching address records
			break
		}

		// Check for CNAME loop
		for _, seen := range cnameChain {
			if seen == nextCNAME {
				return nil, ErrCNAMELoop
			}
		}

		if cnameTTL < minTTL {
			minTTL = cnameTTL
		}
		cnameChain = append(cnameChain, nextCNAME)
		currentName = nextCNAME
	}

	if !hasMatchingRecord {
		// Valid response, but no records matching QTYPE for the owned chain -> NODATA
		parseAuthoritySection(msg, offset, 0, nsCount, resp)
		return resp, ErrNoData
	}

	// Clamp TTL: TTL 0 means do not cache (honored). Upper cap at MaxCachedTTLSeconds (86400s).
	if minTTL > MaxCachedTTLSeconds {
		minTTL = MaxCachedTTLSeconds
	}

	resp.IPs = validIPs
	resp.TTL = time.Duration(minTTL) * time.Second

	return resp, nil
}

// parseAuthoritySection parses Authority records looking for a valid SOA record to derive negative TTL (RFC 2308).
func parseAuthoritySection(msg []byte, offset int, anCount uint16, nsCount uint16, resp *Response) {
	if nsCount == 0 || offset >= len(msg) {
		return
	}

	for i := 0; i < int(nsCount); i++ {
		if offset >= len(msg) {
			break
		}
		_, newOff, err := parseDomainName(msg, offset, 0)
		if err != nil {
			return
		}
		offset = newOff

		if offset+10 > len(msg) {
			return
		}

		rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		_ = binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		rrTTL := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(msg[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(msg) {
			return
		}

		rdataOffset := offset
		_ = msg[offset : offset+int(rdLength)]
		offset += int(rdLength)

		if rrType == TypeSOA {
			soa, err := parseSOARdata(msg, rdataOffset, int(rdLength), rrTTL)
			if err == nil {
				resp.HasSOA = true
				resp.SOA = *soa
				// RFC 2308 §5: negative TTL = min(SOA.TTL, SOA.MINIMUM)
				negSec := soa.TTL
				if soa.Minimum < negSec {
					negSec = soa.Minimum
				}
				// Clamp upper bound to 3600s (1 hour) per RFC 2308 §5 recommendations
				if negSec > 3600 {
					negSec = 3600
				}
				resp.NegativeTTL = time.Duration(negSec) * time.Second
				return
			}
		}
	}
}

// parseSOARdata parses the MNAME, RNAME, and fixed timer fields of an SOA RDATA buffer.
func parseSOARdata(msg []byte, offset int, rdLength int, rrTTL uint32) (*SOARecord, error) {
	end := offset + rdLength
	// SOA RDATA: MNAME, RNAME, SERIAL (4), REFRESH (4), RETRY (4), EXPIRE (4), MINIMUM (4)
	mname, off, err := parseDomainName(msg, offset, 0)
	if err != nil {
		return nil, err
	}
	rname, off, err := parseDomainName(msg, off, 0)
	if err != nil {
		return nil, err
	}

	if off+20 > end || off+20 > len(msg) {
		return nil, errors.New("truncated SOA numeric fields")
	}

	serial := binary.BigEndian.Uint32(msg[off : off+4])
	refresh := binary.BigEndian.Uint32(msg[off+4 : off+8])
	retry := binary.BigEndian.Uint32(msg[off+8 : off+12])
	expire := binary.BigEndian.Uint32(msg[off+12 : off+16])
	minimum := binary.BigEndian.Uint32(msg[off+16 : off+20])

	return &SOARecord{
		MName:   mname,
		RName:   rname,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
		TTL:     rrTTL,
	}, nil
}

// parseDomainName decodes wire-format labels or compression pointers (0xC0..) into a dotted string.
func parseDomainName(msg []byte, offset int, depth int) (string, int, error) {
	if depth > MaxCompressionPointer {
		return "", 0, ErrPointerLoop
	}

	var labels []string
	origOffset := offset
	jumped := false

	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("%w: offset %d out of bounds", ErrMalformedMessage, offset)
		}

		b := msg[offset]
		if b == 0 {
			// Null byte terminates the domain name
			if !jumped {
				origOffset = offset + 1
			}
			break
		}

		// Check for compression pointer (top two bits set: 11xxxxxx)
		if (b & 0xC0) == 0xC0 {
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("%w: truncated compression pointer", ErrMalformedMessage)
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			if ptr >= len(msg) {
				return "", 0, ErrInvalidPointer
			}

			if !jumped {
				origOffset = offset + 2
				jumped = true
			}

			targetName, _, err := parseDomainName(msg, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if len(targetName) > 0 {
				labels = append(labels, targetName)
			}
			break
		}

		// Standard uncompressed label
		labelLen := int(b)
		offset++
		if labelLen > MaxLabelLength {
			return "", 0, fmt.Errorf("%w: label length %d > 63", ErrMalformedMessage, labelLen)
		}
		if offset+labelLen > len(msg) {
			return "", 0, fmt.Errorf("%w: truncated label", ErrMalformedMessage)
		}

		labels = append(labels, string(msg[offset:offset+labelLen]))
		offset += labelLen

		if !jumped {
			origOffset = offset
		}
	}

	return strings.Join(labels, "."), origOffset, nil
}

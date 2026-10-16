package packetlab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Standard protocol lengths and constants (RFC 791, RFC 793).
const (
	MinIPv4HeaderLen = 20
	MinTCPHeaderLen  = 20
	MinPacketLen     = MinIPv4HeaderLen + MinTCPHeaderLen
	MaxIPv4PacketLen = 65535

	IPv4ProtoTCP = 6

	// TCP Control Flags (RFC 793, RFC 3168).
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
	TCPFlagECE = 0x40
	TCPFlagCWR = 0x80

	// Default dummy SNI for synthetic ClientHello payload generation.
	DefaultDummySNI = "www.example.com"

	// Hop count boundaries for synthetic low-TTL packet injection.
	MinFakeTTL = 2
	MaxFakeTTL = 16

	// MaxSegmentPayload defines the maximum allowable TCP payload size (1400 bytes)
	// when re-injecting split segments, ensuring the total IPv4 datagram size
	// never exceeds standard Ethernet MTU (1500 bytes) even with IP and TCP options.
	MaxSegmentPayload = 1400
)

// Well-defined error values for packet parsing and segmentation validation.
var (
	ErrPacketTooShort          = errors.New("packet buffer shorter than minimum IPv4/TCP headers (40 bytes)")
	ErrPacketTooLarge          = errors.New("packet exceeds maximum IPv4 packet size (65535 bytes)")
	ErrNotIPv4                 = errors.New("packet is not IPv4")
	ErrInvalidIHL              = errors.New("invalid IPv4 header length (IHL must be between 5 and 15 words)")
	ErrTruncatedIPv4Header     = errors.New("packet buffer truncated relative to IPv4 header length")
	ErrInvalidTotalLength      = errors.New("IPv4 total length is smaller than header length")
	ErrTruncatedIPv4Packet     = errors.New("packet buffer truncated relative to IPv4 total length")
	ErrInconsistentTotalLength = errors.New("packet buffer length does not match IPv4 total length (inconsistent length fields)")
	ErrNotTCP                  = errors.New("IPv4 protocol is not TCP")
	ErrIPv4ReservedFlagSet     = errors.New("IPv4 reserved flag bit is set")
	ErrIPv4Fragmented          = errors.New("fragmented IPv4 datagrams are not supported")
	ErrTruncatedTCPHeader      = errors.New("TCP segment shorter than minimum 20-byte TCP header")
	ErrInvalidTCPDataOffset    = errors.New("invalid TCP data offset (must be between 5 and 15 words)")
	ErrTruncatedTCPOptions     = errors.New("TCP segment truncated relative to TCP header length")
	ErrTCPReservedBitsSet      = errors.New("TCP reserved bits or NS flag are set")
	ErrMissingACKFlag          = errors.New("TCP packet missing required ACK flag")
	ErrUnsupportedTCPFlags     = errors.New("unsupported TCP control flags (only ACK and ACK|PSH supported)")
	ErrEmptyTCPPayload         = errors.New("TCP packet has empty payload")
	ErrPayloadTooShort         = errors.New("TCP payload too short to split into two nonempty parts (must be at least 2 bytes)")
	ErrSplitOffsetOutOfBounds  = errors.New("split offset is out of bounds for payload length")
	ErrInvalidFakeTTL          = errors.New("fake packet TTL must be between 2 and 16")
	ErrEmptyDummyPayload       = errors.New("dummy payload cannot be empty")
)

// ParsedPacket represents the validated fields of an IPv4/TCP packet.
type ParsedPacket struct {
	IHL            int
	TotalLength    int
	Identification uint16
	DF             bool
	TTL            uint8
	Protocol       uint8
	SrcIP          net.IP
	DstIP          net.IP
	IPv4Options    []byte

	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	TCPDataOffset int
	TCPFlags      uint8
	Window        uint16
	TCPOptions    []byte
	Payload       []byte
}

// PacketConfig holds parameters for constructing synthetic IPv4/TCP packets.
type PacketConfig struct {
	SrcIP          [4]byte
	DstIP          [4]byte
	SrcPort        uint16
	DstPort        uint16
	SeqNum         uint32
	AckNum         uint32
	TCPFlags       uint8
	Window         uint16
	Identification uint16
	DF             bool
	TTL            uint8
	IPv4Options    []byte
	TCPOptions     []byte
	Payload        []byte
}

// DefaultPacketConfig returns a standard PacketConfig suitable for testing.
func DefaultPacketConfig() PacketConfig {
	return PacketConfig{
		SrcIP:          [4]byte{127, 0, 0, 1},
		DstIP:          [4]byte{127, 0, 0, 1},
		SrcPort:        12345,
		DstPort:        54321,
		SeqNum:         1000,
		AckNum:         2000,
		TCPFlags:       TCPFlagACK | TCPFlagPSH,
		Window:         65535,
		Identification: 0x1234,
		DF:             true,
		TTL:            64,
		Payload:        []byte("Hello, packetlab deterministic segmentation test!"),
	}
}

// BuildIPv4TCPPacket constructs a valid IPv4/TCP packet with recomputed checksums.
func BuildIPv4TCPPacket(cfg PacketConfig) ([]byte, error) {
	if len(cfg.IPv4Options)%4 != 0 {
		return nil, errors.New("IPv4 options length must be a multiple of 4 bytes")
	}
	ihl := MinIPv4HeaderLen + len(cfg.IPv4Options)
	if ihl > 60 {
		return nil, errors.New("IPv4 header length exceeds maximum 60 bytes")
	}

	if len(cfg.TCPOptions)%4 != 0 {
		return nil, errors.New("TCP options length must be a multiple of 4 bytes")
	}
	tcpOffset := MinTCPHeaderLen + len(cfg.TCPOptions)
	if tcpOffset > 60 {
		return nil, errors.New("TCP header length exceeds maximum 60 bytes")
	}

	totalLen := ihl + tcpOffset + len(cfg.Payload)
	if totalLen > MaxIPv4PacketLen {
		return nil, ErrPacketTooLarge
	}

	packet := make([]byte, totalLen)

	// IPv4 Header
	packet[0] = (4 << 4) | byte(ihl/4)
	packet[1] = 0 // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], cfg.Identification)

	var fragWord uint16
	if cfg.DF {
		fragWord |= 0x4000
	}
	binary.BigEndian.PutUint16(packet[6:8], fragWord)

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 64
	}
	packet[8] = ttl
	packet[9] = IPv4ProtoTCP
	copy(packet[12:16], cfg.SrcIP[:])
	copy(packet[16:20], cfg.DstIP[:])

	if len(cfg.IPv4Options) > 0 {
		copy(packet[20:ihl], cfg.IPv4Options)
	}

	// Calculate and store IPv4 checksum
	ipCS := IPv4Checksum(packet[:ihl])
	binary.BigEndian.PutUint16(packet[10:12], ipCS)

	// TCP Header
	tcpStart := ihl
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], cfg.SrcPort)
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], cfg.DstPort)
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], cfg.SeqNum)
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], cfg.AckNum)
	packet[tcpStart+12] = byte(tcpOffset/4) << 4
	packet[tcpStart+13] = cfg.TCPFlags

	win := cfg.Window
	if win == 0 {
		win = 65535
	}
	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], win)
	// Checksum initially 0
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], 0)
	binary.BigEndian.PutUint16(packet[tcpStart+18:tcpStart+20], 0) // Urgent pointer

	if len(cfg.TCPOptions) > 0 {
		copy(packet[tcpStart+20:tcpStart+tcpOffset], cfg.TCPOptions)
	}

	// Payload
	if len(cfg.Payload) > 0 {
		copy(packet[tcpStart+tcpOffset:], cfg.Payload)
	}

	// Calculate and store TCP checksum
	tcpCS, err := TCPChecksum(packet[12:16], packet[16:20], packet[tcpStart:tcpStart+tcpOffset], cfg.Payload)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], tcpCS)

	return packet, nil
}

// ParseIPv4TCPPacket inspects and validates an IPv4/TCP packet without mutating the input.
func ParseIPv4TCPPacket(packet []byte) (*ParsedPacket, error) {
	if len(packet) < MinPacketLen {
		return nil, ErrPacketTooShort
	}
	if len(packet) > MaxIPv4PacketLen {
		return nil, ErrPacketTooLarge
	}

	// IPv4 Version and IHL
	version := packet[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("%w: version %d", ErrNotIPv4, version)
	}
	ihlWords := int(packet[0] & 0x0F)
	if ihlWords < 5 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidIHL, ihlWords)
	}
	ihl := ihlWords * 4
	if len(packet) < ihl {
		return nil, fmt.Errorf("%w: buffer has %d bytes, header needs %d", ErrTruncatedIPv4Header, len(packet), ihl)
	}

	// Total length
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl {
		return nil, fmt.Errorf("%w: totalLen %d < ihl %d", ErrInvalidTotalLength, totalLen, ihl)
	}
	if len(packet) < totalLen {
		return nil, fmt.Errorf("%w: buffer has %d bytes, totalLen is %d", ErrTruncatedIPv4Packet, len(packet), totalLen)
	}
	if len(packet) > totalLen {
		return nil, fmt.Errorf("%w: buffer has %d bytes, totalLen claims %d", ErrInconsistentTotalLength, len(packet), totalLen)
	}

	// Protocol check
	proto := packet[9]
	if proto != IPv4ProtoTCP {
		return nil, fmt.Errorf("%w: got %d", ErrNotTCP, proto)
	}

	// Flags and fragment offset
	fragWord := binary.BigEndian.Uint16(packet[6:8])
	if (fragWord & 0x8000) != 0 {
		return nil, ErrIPv4ReservedFlagSet
	}
	mf := (fragWord & 0x2000) != 0
	fragOffset := fragWord & 0x1FFF
	if mf || fragOffset != 0 {
		return nil, fmt.Errorf("%w: MF=%v, offset=%d", ErrIPv4Fragmented, mf, fragOffset)
	}
	df := (fragWord & 0x4000) != 0

	// TCP boundary checks
	tcpLen := totalLen - ihl
	if tcpLen < MinTCPHeaderLen {
		return nil, fmt.Errorf("%w: tcpLen is %d bytes", ErrTruncatedTCPHeader, tcpLen)
	}

	tcpDataOffsetWords := int(packet[ihl+12] >> 4)
	if tcpDataOffsetWords < 5 {
		return nil, fmt.Errorf("%w: data offset is %d words", ErrInvalidTCPDataOffset, tcpDataOffsetWords)
	}
	tcpDataOffset := tcpDataOffsetWords * 4
	if tcpLen < tcpDataOffset {
		return nil, fmt.Errorf("%w: tcpLen %d < header length %d", ErrTruncatedTCPOptions, tcpLen, tcpDataOffset)
	}

	// Reserved bits and NS flag
	if (packet[ihl+12] & 0x0F) != 0 {
		return nil, fmt.Errorf("%w: 0x%x", ErrTCPReservedBitsSet, packet[ihl+12]&0x0F)
	}

	// TCP flags validation (conservatively support only ACK and ACK|PSH)
	tcpFlags := packet[ihl+13]
	if (tcpFlags & TCPFlagACK) == 0 {
		return nil, fmt.Errorf("%w: flags=0x%02x", ErrMissingACKFlag, tcpFlags)
	}
	unsupported := tcpFlags & (TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagURG | TCPFlagECE | TCPFlagCWR)
	if unsupported != 0 {
		return nil, fmt.Errorf("%w: 0x%02x (unsupported bits: 0x%02x)", ErrUnsupportedTCPFlags, tcpFlags, unsupported)
	}

	payloadLen := totalLen - ihl - tcpDataOffset
	if payloadLen <= 0 {
		return nil, fmt.Errorf("%w: payload length is %d", ErrEmptyTCPPayload, payloadLen)
	}

	parsed := &ParsedPacket{
		IHL:            ihl,
		TotalLength:    totalLen,
		Identification: binary.BigEndian.Uint16(packet[4:6]),
		DF:             df,
		TTL:            packet[8],
		Protocol:       proto,
		SrcIP:          append(net.IP(nil), packet[12:16]...),
		DstIP:          append(net.IP(nil), packet[16:20]...),
		SrcPort:        binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		DstPort:        binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
		SeqNum:         binary.BigEndian.Uint32(packet[ihl+4 : ihl+8]),
		AckNum:         binary.BigEndian.Uint32(packet[ihl+8 : ihl+12]),
		TCPDataOffset:  tcpDataOffset,
		TCPFlags:       tcpFlags,
		Window:         binary.BigEndian.Uint16(packet[ihl+14 : ihl+16]),
		Payload:        packet[ihl+tcpDataOffset : totalLen],
	}

	if ihl > MinIPv4HeaderLen {
		parsed.IPv4Options = append([]byte(nil), packet[MinIPv4HeaderLen:ihl]...)
	}
	if tcpDataOffset > MinTCPHeaderLen {
		parsed.TCPOptions = append([]byte(nil), packet[ihl+MinTCPHeaderLen:ihl+tcpDataOffset]...)
	}

	return parsed, nil
}

// SplitIPv4TCPPacket splits an eligible IPv4/TCP packet into two valid packets at splitOffset.
//
// Semantics:
//  1. Pure function: does not mutate caller input; fail-closed on any error with nil results.
//  2. Input packet must carry non-empty TCP payload, have ACK set, and have no unsupported flags
//     (SYN, FIN, RST, URG, ECE, CWR).
//  3. splitOffset must satisfy 0 < splitOffset < payloadLen.
//  4. First segment carries payload[:splitOffset] with original sequence number and ACK (PSH cleared).
//  5. Second segment carries payload[splitOffset:] with sequence number advanced by splitOffset,
//     preserving original PSH flag if present.
//  6. IPv4 and TCP options, window, acknowledgement number, connection tuple, and payload bytes are preserved.
//  7. Checksums for IPv4 header and TCP pseudo-header are recomputed for both segments.
func SplitIPv4TCPPacket(packet []byte, splitOffset int) (first []byte, second []byte, err error) {
	parsed, err := ParseIPv4TCPPacket(packet)
	if err != nil {
		return nil, nil, err
	}

	payloadLen := len(parsed.Payload)
	if payloadLen < 2 {
		return nil, nil, fmt.Errorf("%w: payload length is %d", ErrPayloadTooShort, payloadLen)
	}
	if splitOffset <= 0 || splitOffset >= payloadLen {
		return nil, nil, fmt.Errorf("%w: offset %d not strictly inside (0, %d)", ErrSplitOffsetOutOfBounds, splitOffset, payloadLen)
	}

	ihl := parsed.IHL
	tcpDataOffset := parsed.TCPDataOffset

	seg1PayloadLen := splitOffset
	seg2PayloadLen := payloadLen - splitOffset

	seg1TotalLen := ihl + tcpDataOffset + seg1PayloadLen
	seg2TotalLen := ihl + tcpDataOffset + seg2PayloadLen

	if seg1TotalLen > MaxIPv4PacketLen || seg2TotalLen > MaxIPv4PacketLen {
		return nil, nil, ErrPacketTooLarge
	}

	first = make([]byte, seg1TotalLen)
	second = make([]byte, seg2TotalLen)

	var fragWord uint16
	if parsed.DF {
		fragWord |= 0x4000
	}

	// ---------------- Segment 1 ----------------
	// Copy IPv4 header
	copy(first[:ihl], packet[:ihl])
	binary.BigEndian.PutUint16(first[2:4], uint16(seg1TotalLen))
	binary.BigEndian.PutUint16(first[4:6], parsed.Identification)
	binary.BigEndian.PutUint16(first[6:8], fragWord)
	binary.BigEndian.PutUint16(first[10:12], 0) // zero checksum field before calculation
	firstIPCS := IPv4Checksum(first[:ihl])
	binary.BigEndian.PutUint16(first[10:12], firstIPCS)

	// Copy TCP header
	copy(first[ihl:ihl+tcpDataOffset], packet[ihl:ihl+tcpDataOffset])
	// Sequence number is original
	binary.BigEndian.PutUint32(first[ihl+4:ihl+8], parsed.SeqNum)
	// PSH cleared on first segment
	first[ihl+13] = parsed.TCPFlags & ^byte(TCPFlagPSH)
	binary.BigEndian.PutUint16(first[ihl+16:ihl+18], 0) // zero checksum field before calculation

	// Copy payload slice 1
	seg1Payload := parsed.Payload[:seg1PayloadLen]
	copy(first[ihl+tcpDataOffset:], seg1Payload)

	// Compute TCP checksum for segment 1
	firstTCPCS, err := TCPChecksum(first[12:16], first[16:20], first[ihl:ihl+tcpDataOffset], seg1Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed calculating segment 1 TCP checksum: %w", err)
	}
	binary.BigEndian.PutUint16(first[ihl+16:ihl+18], firstTCPCS)

	// ---------------- Segment 2 ----------------
	// Copy IPv4 header
	copy(second[:ihl], packet[:ihl])
	binary.BigEndian.PutUint16(second[2:4], uint16(seg2TotalLen))
	// Increment identification for the second datagram
	binary.BigEndian.PutUint16(second[4:6], parsed.Identification+1)
	binary.BigEndian.PutUint16(second[6:8], fragWord)
	binary.BigEndian.PutUint16(second[10:12], 0) // zero checksum field before calculation
	secondIPCS := IPv4Checksum(second[:ihl])
	binary.BigEndian.PutUint16(second[10:12], secondIPCS)

	// Copy TCP header
	copy(second[ihl:ihl+tcpDataOffset], packet[ihl:ihl+tcpDataOffset])
	// Advance sequence number by seg1PayloadLen (32-bit modulo wrapping)
	seg2Seq := parsed.SeqNum + uint32(seg1PayloadLen)
	binary.BigEndian.PutUint32(second[ihl+4:ihl+8], seg2Seq)
	// Segment 2 inherits original flags (preserves PSH if present)
	second[ihl+13] = parsed.TCPFlags
	binary.BigEndian.PutUint16(second[ihl+16:ihl+18], 0) // zero checksum field before calculation

	// Copy payload slice 2
	seg2Payload := parsed.Payload[seg1PayloadLen:]
	copy(second[ihl+tcpDataOffset:], seg2Payload)

	// Compute TCP checksum for segment 2
	secondTCPCS, err := TCPChecksum(second[12:16], second[16:20], second[ihl:ihl+tcpDataOffset], seg2Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed calculating segment 2 TCP checksum: %w", err)
	}
	binary.BigEndian.PutUint16(second[ihl+16:ihl+18], secondTCPCS)

	return first, second, nil
}

// SubsegmentIPv4TCPPacket checks if the supplied IPv4/TCP packet exceeds maxPayload bytes
// (defaulting to MaxSegmentPayload = 1400 if maxPayload <= 0). If it does, the packet
// is subdivided into contiguous chunks of at most maxPayload bytes, preserving contiguous
// sequence numbers, connection 4-tuples, IP/TCP options, and recomputing valid RFC 791
// IPv4 header checksums and RFC 793 TCP pseudo-header checksums for every chunk.
// If the payload is already <= maxPayload, a single-element slice containing a defensive
// copy of the packet is returned.
func SubsegmentIPv4TCPPacket(packet []byte, maxPayload int) ([][]byte, error) {
	if len(packet) < MinPacketLen {
		return nil, ErrPacketTooShort
	}
	parsed, err := ParseIPv4TCPPacket(packet)
	if err != nil {
		return nil, err
	}

	if maxPayload <= 0 || maxPayload > 1460 {
		maxPayload = MaxSegmentPayload
	}

	ihl := parsed.IHL
	tcpDataOffset := parsed.TCPDataOffset

	// Guarantee that the total IPv4 datagram size (headers + chunk) never exceeds standard 1500 MTU
	if ihl+tcpDataOffset+maxPayload > 1500 {
		maxPayload = 1500 - (ihl + tcpDataOffset)
	}

	payloadLen := len(parsed.Payload)
	if payloadLen <= maxPayload {
		cp := append([]byte(nil), packet...)
		return [][]byte{cp}, nil
	}

	var segments [][]byte
	for offset := 0; offset < payloadLen; offset += maxPayload {
		chunkEnd := offset + maxPayload
		isLast := false
		if chunkEnd >= payloadLen {
			chunkEnd = payloadLen
			isLast = true
		}
		chunk := parsed.Payload[offset:chunkEnd]
		chunkLen := len(chunk)

		segTotalLen := ihl + tcpDataOffset + chunkLen
		if segTotalLen > MaxIPv4PacketLen {
			return nil, ErrPacketTooLarge
		}

		seg := make([]byte, segTotalLen)

		// 1. Copy IPv4 header and update length, ID, flags, checksum
		copy(seg[:ihl], packet[:ihl])
		binary.BigEndian.PutUint16(seg[2:4], uint16(segTotalLen))
		chunkIndex := len(segments)
		binary.BigEndian.PutUint16(seg[4:6], parsed.Identification+uint16(chunkIndex))

		var fragWord uint16
		if parsed.DF {
			fragWord |= 0x4000
		}
		binary.BigEndian.PutUint16(seg[6:8], fragWord)
		binary.BigEndian.PutUint16(seg[10:12], 0)
		ipCS := IPv4Checksum(seg[:ihl])
		binary.BigEndian.PutUint16(seg[10:12], ipCS)

		// 2. Copy TCP header and update sequence number, flags, checksum
		copy(seg[ihl:ihl+tcpDataOffset], packet[ihl:ihl+tcpDataOffset])
		segSeq := parsed.SeqNum + uint32(offset)
		binary.BigEndian.PutUint32(seg[ihl+4:ihl+8], segSeq)

		if isLast {
			seg[ihl+13] = parsed.TCPFlags
		} else {
			seg[ihl+13] = parsed.TCPFlags & ^byte(TCPFlagPSH)
		}
		binary.BigEndian.PutUint16(seg[ihl+16:ihl+18], 0)

		// 3. Copy chunk payload
		copy(seg[ihl+tcpDataOffset:], chunk)

		// 4. Compute TCP checksum
		tcpCS, err := TCPChecksum(seg[12:16], seg[16:20], seg[ihl:ihl+tcpDataOffset], chunk)
		if err != nil {
			return nil, fmt.Errorf("calculate subsegment TCP checksum: %w", err)
		}
		binary.BigEndian.PutUint16(seg[ihl+16:ihl+18], tcpCS)

		segments = append(segments, seg)
	}

	return segments, nil
}

// IPv4Checksum computes the RFC 791 / RFC 1071 Internet Checksum over an IPv4 header.
// Per RFC 791, the checksum field (bytes 10..12) is treated as zero during calculation.
// If the computed one's complement checksum is zero, RFC 1071 / RFC 1624 specifies
// representing it as 0xFFFF (negative zero).
func IPv4Checksum(header []byte) uint16 {
	if len(header) < MinIPv4HeaderLen {
		return 0
	}
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue // Checksum field is treated as zero per RFC 791
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xFFFF
	}
	return c
}

// TCPChecksum computes the RFC 793 / RFC 1071 TCP checksum using the IPv4 pseudo-header,
// the TCP header (with checksum field at bytes 16..18 treated as zero), and the TCP payload.
func TCPChecksum(srcIP, dstIP []byte, tcpHeader, payload []byte) (uint16, error) {
	if len(srcIP) != 4 || len(dstIP) != 4 {
		return 0, fmt.Errorf("invalid IPv4 address length for pseudo-header: src=%d, dst=%d", len(srcIP), len(dstIP))
	}
	if len(tcpHeader) < MinTCPHeaderLen {
		return 0, ErrTruncatedTCPHeader
	}
	if len(tcpHeader)%4 != 0 {
		return 0, errors.New("TCP header length must be a multiple of 4 bytes")
	}
	tcpLen := len(tcpHeader) + len(payload)
	if tcpLen > MaxIPv4PacketLen {
		return 0, errors.New("TCP segment length exceeds maximum 65535 bytes")
	}

	var sum uint32

	// IPv4 Pseudo-Header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(IPv4ProtoTCP)
	sum += uint32(tcpLen)

	// TCP Header (checksum field at offset 16 is treated as 0 per RFC 793)
	for i := 0; i+1 < len(tcpHeader); i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcpHeader[i : i+2]))
	}

	// Payload
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xFFFF
	}
	return c, nil
}

// VerifyIPv4Checksum independently validates the checksum of an IPv4 header in a raw packet.
func VerifyIPv4Checksum(packet []byte) (bool, error) {
	if len(packet) < MinIPv4HeaderLen {
		return false, ErrPacketTooShort
	}
	if packet[0]>>4 != 4 {
		return false, ErrNotIPv4
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < MinIPv4HeaderLen || len(packet) < ihl {
		return false, ErrInvalidIHL
	}
	// The one's complement sum of a valid header including the checksum is 0 (or ~sum == 0).
	var sum uint32
	for i := 0; i+1 < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) == 0, nil
}

// VerifyTCPChecksum independently validates the TCP checksum in an IPv4 packet.
func VerifyTCPChecksum(packet []byte) (bool, error) {
	if len(packet) < MinPacketLen {
		return false, ErrPacketTooShort
	}
	if packet[0]>>4 != 4 {
		return false, ErrNotIPv4
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < MinIPv4HeaderLen {
		return false, ErrInvalidIHL
	}
	if len(packet) < ihl {
		return false, ErrTruncatedIPv4Header
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || len(packet) < totalLen {
		return false, ErrTruncatedIPv4Packet
	}
	if packet[9] != IPv4ProtoTCP {
		return false, ErrNotTCP
	}

	tcpLen := totalLen - ihl
	if tcpLen < MinTCPHeaderLen {
		return false, ErrTruncatedTCPHeader
	}

	srcIP := packet[12:16]
	dstIP := packet[16:20]
	tcpSegment := packet[ihl:totalLen]

	var sum uint32
	// Pseudo-Header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(IPv4ProtoTCP)
	sum += uint32(tcpLen)

	// TCP Segment (header + payload, with existing checksum included)
	for i := 0; i+1 < len(tcpSegment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
	}
	if len(tcpSegment)%2 != 0 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) == 0, nil
}

// BuildDummyClientHello constructs a structurally valid TLS ClientHello wrapped in a
// single TLS record (0x16 0x03 0x01 ...) containing the specified Server Name Indication (SNI).
// If sni is empty, DefaultDummySNI ("www.example.com") is used.
// The returned byte slice is directly parseable by tlsparse.ParseClientHello.
func BuildDummyClientHello(sni string) []byte {
	sni = strings.TrimSpace(sni)
	if sni == "" {
		sni = DefaultDummySNI
	}
	if len(sni) > 255 {
		sni = sni[:255]
	}

	handshakeBody := bytes.Buffer{}

	// Legacy Version: TLS 1.2 (0x0303)
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x0303))

	// Client Random: 32 bytes (deterministic 0x42)
	handshakeBody.Write(bytes.Repeat([]byte{0x42}, 32))

	// Session ID length: 0
	handshakeBody.WriteByte(0x00)

	// Cipher Suites: 2 suites (0x1301 TLS_AES_128_GCM_SHA256, 0xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(4))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x1301))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0xc02f))

	// Compression Methods: 1 method (0x00 null)
	handshakeBody.WriteByte(0x01)
	handshakeBody.WriteByte(0x00)

	// Extensions block
	extensionsBuf := bytes.Buffer{}

	// SNI Extension (Type 0x0000)
	sniBytes := []byte(sni)
	serverNameListLen := uint16(1 + 2 + len(sniBytes))
	sniExtLen := uint16(2 + serverNameListLen)

	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x0000))
	_ = binary.Write(&extensionsBuf, binary.BigEndian, sniExtLen)
	_ = binary.Write(&extensionsBuf, binary.BigEndian, serverNameListLen)
	extensionsBuf.WriteByte(0x00) // NameType: host_name (0)
	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(len(sniBytes)))
	extensionsBuf.Write(sniBytes)

	if extensionsBuf.Len() > 0 {
		_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(extensionsBuf.Len()))
		handshakeBody.Write(extensionsBuf.Bytes())
	}

	// Full Handshake message: Type 0x01 (ClientHello) + uint24 length + body
	fullHandshake := bytes.Buffer{}
	fullHandshake.WriteByte(0x01)
	bodyLen := handshakeBody.Len()
	fullHandshake.WriteByte(byte(bodyLen >> 16))
	fullHandshake.WriteByte(byte(bodyLen >> 8))
	fullHandshake.WriteByte(byte(bodyLen & 0xFF))
	fullHandshake.Write(handshakeBody.Bytes())

	// Wrap in TLS Record Header (ContentType 0x16, Version 0x0301, Length)
	record := bytes.Buffer{}
	record.WriteByte(0x16)
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(fullHandshake.Len()))
	record.Write(fullHandshake.Bytes())

	return record.Bytes()
}

// SynthesizeFakeIPv4TCPPacket creates a synthetic fake packet by cloning the original packet's
// IPv4 and TCP headers (preserving identical connection 4-tuple, SeqNum, AckNum, Window size,
// flags, and options), replacing the TCP payload with dummyPayload, and applying configured
// evasion options:
//   - If fakeTTL > 0: sets the IPv4 TTL to fakeTTL (must be in range 2-16) and recomputes the IPv4 checksum.
//   - If badChecksum is true: deliberately corrupts the RFC 793 TCP checksum so destination OS unconditionally discards it.
//
// The originalPacket slice is never mutated.
func SynthesizeFakeIPv4TCPPacket(originalPacket []byte, dummyPayload []byte, fakeTTL uint8, badChecksum bool) ([]byte, error) {
	if len(dummyPayload) == 0 {
		return nil, ErrEmptyDummyPayload
	}
	if fakeTTL > 0 && (fakeTTL < MinFakeTTL || fakeTTL > MaxFakeTTL) {
		return nil, ErrInvalidFakeTTL
	}

	parsed, err := ParseIPv4TCPPacket(originalPacket)
	if err != nil {
		return nil, err
	}

	ihl := parsed.IHL
	tcpDataOffset := parsed.TCPDataOffset
	totalLen := ihl + tcpDataOffset + len(dummyPayload)
	if totalLen > MaxIPv4PacketLen {
		return nil, ErrPacketTooLarge
	}

	fake := make([]byte, totalLen)

	// 1. Clone IPv4 header
	copy(fake[:ihl], originalPacket[:ihl])
	binary.BigEndian.PutUint16(fake[2:4], uint16(totalLen))
	if fakeTTL > 0 {
		fake[8] = fakeTTL
	}
	// Zero checksum field before recalculation per RFC 791
	binary.BigEndian.PutUint16(fake[10:12], 0)
	ipCS := IPv4Checksum(fake[:ihl])
	binary.BigEndian.PutUint16(fake[10:12], ipCS)

	// 2. Clone TCP header (identical 4-tuple, SeqNum, AckNum, Window, flags, options)
	copy(fake[ihl:ihl+tcpDataOffset], originalPacket[ihl:ihl+tcpDataOffset])
	// Zero TCP checksum field before calculation per RFC 793
	binary.BigEndian.PutUint16(fake[ihl+16:ihl+18], 0)

	// 3. Insert dummy payload
	copy(fake[ihl+tcpDataOffset:], dummyPayload)

	// 4. Compute TCP checksum
	tcpCS, err := TCPChecksum(fake[12:16], fake[16:20], fake[ihl:ihl+tcpDataOffset], dummyPayload)
	if err != nil {
		return nil, fmt.Errorf("calculate fake TCP checksum: %w", err)
	}

	if badChecksum {
		// Deliberately invert or corrupt RFC 793 TCP checksum
		badCS := ^tcpCS
		if badCS == 0 {
			badCS = 0xBAAD
		}
		binary.BigEndian.PutUint16(fake[ihl+16:ihl+18], badCS)

		// Sanity check: guarantee that VerifyTCPChecksum reports invalid
		if valid, _ := VerifyTCPChecksum(fake); valid {
			badCS ^= 0x55AA
			binary.BigEndian.PutUint16(fake[ihl+16:ihl+18], badCS)
		}
	} else {
		binary.BigEndian.PutUint16(fake[ihl+16:ihl+18], tcpCS)
	}

	return fake, nil
}

// BuildDummyHTTPRequest constructs a benign plain HTTP GET request directed at host.
// If host is empty, DefaultDummySNI ("www.example.com") is used.
func BuildDummyHTTPRequest(host string) []byte {
	host = strings.TrimSpace(host)
	if host == "" {
		host = DefaultDummySNI
	}
	return []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))
}

// FindHTTPHost parses an unencrypted HTTP request payload to locate the Host header value.
// It returns the trimmed host string, the start and end byte offsets of the host value
// within the payload slice, and whether the header was found.
// The search is case-insensitive and respects RFC 7230 / RFC 9110 HTTP/1.1 header formatting.
func FindHTTPHost(payload []byte) (host string, valStart int, valEnd int, found bool) {
	if len(payload) < 4 {
		return "", 0, 0, false
	}

	offset := 0
	for offset < len(payload) {
		lineEnd := bytes.IndexByte(payload[offset:], '\n')
		var line []byte
		var nextOffset int
		if lineEnd == -1 {
			line = payload[offset:]
			nextOffset = len(payload)
		} else {
			line = payload[offset : offset+lineEnd]
			nextOffset = offset + lineEnd + 1
		}

		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if len(line) == 0 && offset > 0 {
			break
		}

		if len(line) >= 5 {
			prefix := line[:5]
			if (prefix[0] == 'H' || prefix[0] == 'h') &&
				(prefix[1] == 'O' || prefix[1] == 'o') &&
				(prefix[2] == 'S' || prefix[2] == 's') &&
				(prefix[3] == 'T' || prefix[3] == 't') &&
				prefix[4] == ':' {

				vStartInLine := 5
				for vStartInLine < len(line) && (line[vStartInLine] == ' ' || line[vStartInLine] == '\t') {
					vStartInLine++
				}

				vEndInLine := len(line)
				for vEndInLine > vStartInLine && (line[vEndInLine-1] == ' ' || line[vEndInLine-1] == '\t') {
					vEndInLine--
				}

				if vEndInLine > vStartInLine {
					valStart = offset + vStartInLine
					valEnd = offset + vEndInLine
					host = string(payload[valStart:valEnd])
					return host, valStart, valEnd, true
				}
			}
		}

		offset = nextOffset
	}

	return "", 0, 0, false
}

// SynthesizeInboundTCPRSTPacket constructs an inbound IPv4 TCP RST+ACK packet
// from an intercepted outbound IPv4 TCP packet. It swaps Src/Dst IPv4 addresses and
// TCP ports, sets SeqNum = origAckNum, AckNum = origSeqNum + 1, sets TCPFlags = RST|ACK,
// and computes valid RFC 791 IPv4 and RFC 793 TCP checksums.
func SynthesizeInboundTCPRSTPacket(origPacket []byte) ([]byte, error) {
	if len(origPacket) < MinPacketLen {
		return nil, ErrPacketTooShort
	}
	if (origPacket[0] >> 4) != 4 {
		return nil, ErrNotIPv4
	}
	ihl := int(origPacket[0]&0x0F) * 4
	if ihl < MinIPv4HeaderLen || len(origPacket) < ihl+MinTCPHeaderLen {
		return nil, ErrTruncatedIPv4Header
	}
	if origPacket[9] != IPv4ProtoTCP {
		return nil, ErrNotTCP
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], origPacket[16:20]) // Swapped: original DstIP becomes response SrcIP
	copy(dstIP[:], origPacket[12:16]) // Swapped: original SrcIP becomes response DstIP

	srcPort := binary.BigEndian.Uint16(origPacket[ihl+2 : ihl+4]) // Swapped: original DstPort
	dstPort := binary.BigEndian.Uint16(origPacket[ihl : ihl+2])   // Swapped: original SrcPort
	origSeq := binary.BigEndian.Uint32(origPacket[ihl+4 : ihl+8])
	origAck := binary.BigEndian.Uint32(origPacket[ihl+8 : ihl+12])

	tcpDataOffset := int(origPacket[ihl+12]>>4) * 4
	if tcpDataOffset < MinTCPHeaderLen {
		tcpDataOffset = MinTCPHeaderLen
	}
	payloadLen := 0
	if len(origPacket) > ihl+tcpDataOffset {
		payloadLen = len(origPacket) - (ihl + tcpDataOffset)
	}
	ackInc := uint32(1)
	if payloadLen > 1 {
		ackInc = uint32(payloadLen)
	}

	return BuildIPv4TCPPacket(PacketConfig{
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcPort:        srcPort,
		DstPort:        dstPort,
		SeqNum:         origAck,
		AckNum:         origSeq + ackInc,
		TCPFlags:       TCPFlagRST | TCPFlagACK,
		Window:         0,
		Identification: 0x5432,
		DF:             true,
		TTL:            64,
	})
}

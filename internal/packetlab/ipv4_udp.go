package packetlab

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Standard UDP protocol constants (RFC 768).
const (
	IPv4ProtoUDP    = 17
	MinUDPHeaderLen = 8
)

// UDP-specific errors.
var (
	ErrNotUDP             = errors.New("IPv4 protocol is not UDP")
	ErrTruncatedUDPHeader = errors.New("UDP datagram shorter than minimum 8-byte UDP header")
	ErrTruncatedUDPPacket = errors.New("packet buffer truncated relative to UDP length")
	ErrInvalidUDPLength   = errors.New("UDP length is smaller than 8-byte header")
)

// SynthesizeDNSResponseIPv4UDPPacket constructs a synthesized inbound IPv4/UDP packet
// in response to an intercepted outbound DNS query packet:
//   - Swapped 4-tuple:
//     Source IPv4: original DstIP (DNS server)
//     Destination IPv4: original SrcIP (local client)
//     Source Port: original DstPort (53)
//     Destination Port: original SrcPort (client port)
//   - Synthesized 20-byte standard IPv4 header with recomputed RFC 791 checksum.
//   - Synthesized 8-byte UDP header with recomputed RFC 768 checksum (folds to 0xFFFF if 0).
//   - Appends the provided dnsResponsePayload.
func SynthesizeDNSResponseIPv4UDPPacket(queryPacket []byte, dnsResponsePayload []byte) ([]byte, error) {
	if len(queryPacket) < MinIPv4HeaderLen+MinUDPHeaderLen {
		return nil, ErrPacketTooShort
	}
	if (queryPacket[0] >> 4) != 4 {
		return nil, ErrNotIPv4
	}
	ihl := int(queryPacket[0]&0x0F) * 4
	if ihl < MinIPv4HeaderLen || len(queryPacket) < ihl+MinUDPHeaderLen {
		return nil, ErrInvalidIHL
	}
	if queryPacket[9] != IPv4ProtoUDP {
		return nil, fmt.Errorf("%w: got %d", ErrNotUDP, queryPacket[9])
	}

	origSrcIP := queryPacket[12:16]
	origDstIP := queryPacket[16:20]
	origSrcPort := binary.BigEndian.Uint16(queryPacket[ihl : ihl+2])
	origDstPort := binary.BigEndian.Uint16(queryPacket[ihl+2 : ihl+4])

	udpLen := MinUDPHeaderLen + len(dnsResponsePayload)
	totalLen := MinIPv4HeaderLen + udpLen
	if totalLen > MaxIPv4PacketLen {
		return nil, ErrPacketTooLarge
	}

	respPkt := make([]byte, totalLen)

	// 1. IPv4 Header (20 bytes)
	respPkt[0] = 0x45 // Version 4, IHL 5
	respPkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(respPkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(respPkt[4:6], 0)      // Identification
	binary.BigEndian.PutUint16(respPkt[6:8], 0x4000) // DF flag set, fragment offset 0
	respPkt[8] = 64                                  // TTL
	respPkt[9] = IPv4ProtoUDP                        // Protocol 17
	// Checksum placeholder at 10:12 is 0x0000
	copy(respPkt[12:16], origDstIP) // Source IP: original DNS server
	copy(respPkt[16:20], origSrcIP) // Destination IP: original client

	// Compute RFC 791 IPv4 Header Checksum
	var ipSum uint32
	for i := 0; i < MinIPv4HeaderLen; i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(respPkt[i : i+2]))
	}
	for (ipSum >> 16) > 0 {
		ipSum = (ipSum & 0xFFFF) + (ipSum >> 16)
	}
	binary.BigEndian.PutUint16(respPkt[10:12], ^uint16(ipSum))

	// 2. UDP Header (8 bytes at offset 20)
	binary.BigEndian.PutUint16(respPkt[20:22], origDstPort) // Source Port (53)
	binary.BigEndian.PutUint16(respPkt[22:24], origSrcPort) // Destination Port (client)
	binary.BigEndian.PutUint16(respPkt[24:26], uint16(udpLen))
	// Checksum placeholder at 26:28 is 0x0000

	// 3. UDP Payload (at offset 28)
	copy(respPkt[28:], dnsResponsePayload)

	// 4. Compute RFC 768 UDP Checksum
	var udpSum uint32
	// Pseudo-Header
	udpSum += uint32(binary.BigEndian.Uint16(respPkt[12:14])) // SrcIP[0..1]
	udpSum += uint32(binary.BigEndian.Uint16(respPkt[14:16])) // SrcIP[2..3]
	udpSum += uint32(binary.BigEndian.Uint16(respPkt[16:18])) // DstIP[0..1]
	udpSum += uint32(binary.BigEndian.Uint16(respPkt[18:20])) // DstIP[2..3]
	udpSum += uint32(IPv4ProtoUDP)                            // Zero (8-bit) + Protocol (8-bit)
	udpSum += uint32(udpLen)                                  // UDP Length (16-bit)

	// UDP Header + Payload
	udpBytes := respPkt[MinIPv4HeaderLen:totalLen]
	for i := 0; i+1 < len(udpBytes); i += 2 {
		udpSum += uint32(binary.BigEndian.Uint16(udpBytes[i : i+2]))
	}
	if len(udpBytes)%2 != 0 {
		udpSum += uint32(udpBytes[len(udpBytes)-1]) << 8
	}

	for (udpSum >> 16) > 0 {
		udpSum = (udpSum & 0xFFFF) + (udpSum >> 16)
	}
	udpChk := ^uint16(udpSum)
	if udpChk == 0 {
		udpChk = 0xFFFF // RFC 768: 0 is transmitted as 0xFFFF
	}
	binary.BigEndian.PutUint16(respPkt[26:28], udpChk)

	return respPkt, nil
}

// VerifyUDPChecksum independently validates the UDP checksum in an IPv4 packet.
func VerifyUDPChecksum(packet []byte) (bool, error) {
	if len(packet) < MinIPv4HeaderLen+MinUDPHeaderLen {
		return false, ErrPacketTooShort
	}
	if (packet[0] >> 4) != 4 {
		return false, ErrNotIPv4
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < MinIPv4HeaderLen || len(packet) < ihl+MinUDPHeaderLen {
		return false, ErrInvalidIHL
	}
	if packet[9] != IPv4ProtoUDP {
		return false, fmt.Errorf("%w: got %d", ErrNotUDP, packet[9])
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl+MinUDPHeaderLen || len(packet) < totalLen {
		return false, ErrTruncatedIPv4Packet
	}

	udpLen := int(binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]))
	if udpLen < MinUDPHeaderLen {
		return false, ErrInvalidUDPLength
	}
	if ihl+udpLen > totalLen || len(packet) < ihl+udpLen {
		return false, ErrTruncatedUDPPacket
	}

	chk := binary.BigEndian.Uint16(packet[ihl+6 : ihl+8])
	if chk == 0 {
		// RFC 768: Checksum of zero means the sender generated no checksum (allowed)
		return true, nil
	}

	srcIP := packet[12:16]
	dstIP := packet[16:20]
	udpSegment := packet[ihl : ihl+udpLen]

	var sum uint32
	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(IPv4ProtoUDP)
	sum += uint32(udpLen)

	// UDP Segment (header + payload, including checksum)
	for i := 0; i+1 < len(udpSegment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpSegment[i : i+2]))
	}
	if len(udpSegment)%2 != 0 {
		sum += uint32(udpSegment[len(udpSegment)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) == 0, nil
}

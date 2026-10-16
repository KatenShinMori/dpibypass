package packetlab

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// IPv6 protocol constants (RFC 8200).
const (
	IPv6HeaderLen = 40
	IPv6ProtoUDP  = 17
)

var (
	ErrNotIPv6             = errors.New("packet is not IPv6")
	ErrTruncatedIPv6Header = errors.New("packet buffer truncated relative to IPv6 header length")
	ErrIPv6NotUDP          = errors.New("IPv6 upper-layer protocol is not UDP")
)

// IPv6UDPChecksum computes the RFC 8200 / RFC 2460 UDP checksum using the IPv6 pseudo-header,
// the UDP header (with checksum treated as zero), and the UDP payload.
func IPv6UDPChecksum(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) (uint16, error) {
	if len(srcIP) != 16 || len(dstIP) != 16 {
		return 0, fmt.Errorf("invalid IPv6 address length for pseudo-header: src=%d, dst=%d", len(srcIP), len(dstIP))
	}
	udpLen := MinUDPHeaderLen + len(payload)
	if udpLen > MaxIPv4PacketLen {
		return 0, errors.New("UDP datagram length exceeds maximum 65535 bytes")
	}

	var sum uint32

	// 1. IPv6 Pseudo-Header:
	// Source Address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
	}
	// Destination Address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}
	// Upper-Layer Packet Length (32 bits)
	sum += uint32(udpLen)
	// Next Header (32 bits: 3 zero bytes + protocol 17)
	sum += uint32(IPv6ProtoUDP)

	// 2. UDP Header (8 bytes)
	sum += uint32(srcPort)
	sum += uint32(dstPort)
	sum += uint32(udpLen)
	// Checksum field treated as zero

	// 3. UDP Payload
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

// SynthesizeDNSResponseIPv6UDPPacket constructs a synthesized inbound IPv6/UDP packet
// in response to an intercepted outbound IPv6 DNS query packet:
//   - Swapped 4-tuple:
//     Source IPv6: original DstIP (DNS server)
//     Destination IPv6: original SrcIP (local client)
//     Source Port: original DstPort (53)
//     Destination Port: original SrcPort (client port)
//   - Synthesized 40-byte standard IPv6 header (Version 6, NextHeader = 17, HopLimit = 64).
//   - Synthesized 8-byte UDP header with recomputed RFC 8200 checksum.
//   - Appends the provided dnsResponsePayload.
func SynthesizeDNSResponseIPv6UDPPacket(queryPacket []byte, dnsResponsePayload []byte) ([]byte, error) {
	if len(queryPacket) < IPv6HeaderLen+MinUDPHeaderLen {
		return nil, ErrPacketTooShort
	}
	if (queryPacket[0] >> 4) != 6 {
		return nil, ErrNotIPv6
	}

	origSrcIP := queryPacket[8:24]
	origDstIP := queryPacket[24:40]

	// Walk extension headers if present
	nextHeader := queryPacket[6]
	headerLen := IPv6HeaderLen
	for headerLen < len(queryPacket) {
		if nextHeader == IPv6ProtoUDP {
			break
		}
		if nextHeader == 0 || nextHeader == 43 || nextHeader == 60 {
			if headerLen+2 > len(queryPacket) {
				return nil, ErrTruncatedIPv6Header
			}
			extLen := int(queryPacket[headerLen+1]+1) * 8
			if headerLen+extLen > len(queryPacket) {
				return nil, ErrTruncatedIPv6Header
			}
			nextHeader = queryPacket[headerLen]
			headerLen += extLen
			continue
		}
		if nextHeader == 44 { // Fragment
			if headerLen+8 > len(queryPacket) {
				return nil, ErrTruncatedIPv6Header
			}
			nextHeader = queryPacket[headerLen]
			headerLen += 8
			continue
		}
		break
	}

	if nextHeader != IPv6ProtoUDP || headerLen+MinUDPHeaderLen > len(queryPacket) {
		return nil, ErrIPv6NotUDP
	}

	origSrcPort := binary.BigEndian.Uint16(queryPacket[headerLen : headerLen+2])
	origDstPort := binary.BigEndian.Uint16(queryPacket[headerLen+2 : headerLen+4])

	udpLen := MinUDPHeaderLen + len(dnsResponsePayload)
	totalLen := IPv6HeaderLen + udpLen
	if totalLen > MaxIPv4PacketLen {
		return nil, ErrPacketTooLarge
	}

	respPkt := make([]byte, totalLen)

	// 1. IPv6 Header (40 bytes)
	respPkt[0] = 0x60 // Version 6, Traffic Class 0
	respPkt[1] = 0x00
	respPkt[2] = 0x00 // Flow Label 0
	respPkt[3] = 0x00
	binary.BigEndian.PutUint16(respPkt[4:6], uint16(udpLen)) // Payload length
	respPkt[6] = IPv6ProtoUDP                                // NextHeader = 17
	respPkt[7] = 64                                          // Hop Limit
	copy(respPkt[8:24], origDstIP)                           // Source: original DstIP
	copy(respPkt[24:40], origSrcIP)                          // Destination: original SrcIP

	// 2. UDP Header (8 bytes at offset 40)
	binary.BigEndian.PutUint16(respPkt[40:42], origDstPort) // Source Port (53)
	binary.BigEndian.PutUint16(respPkt[42:44], origSrcPort) // Destination Port (client)
	binary.BigEndian.PutUint16(respPkt[44:46], uint16(udpLen))
	// Checksum placeholder at 46:48 is 0x0000

	// 3. UDP Payload (at offset 48)
	copy(respPkt[48:], dnsResponsePayload)

	// 4. Compute RFC 8200 IPv6 UDP Checksum
	cs, err := IPv6UDPChecksum(respPkt[8:24], respPkt[24:40], origDstPort, origSrcPort, dnsResponsePayload)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(respPkt[46:48], cs)

	return respPkt, nil
}

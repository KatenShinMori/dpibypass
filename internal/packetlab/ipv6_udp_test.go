package packetlab

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestSynthesizeDNSResponseIPv6UDPPacket_Success(t *testing.T) {
	// Build a valid IPv6 UDP query packet (40B IPv6 + 8B UDP + 12B DNS query)
	srcIP := net.ParseIP("2001:db8::100").To16()
	dstIP := net.ParseIP("2001:4860:4860::8888").To16()
	srcPort := uint16(54321)
	dstPort := uint16(53)
	dnsQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	queryLen := 40 + 8 + len(dnsQuery)
	queryPkt := make([]byte, queryLen)
	queryPkt[0] = 0x60
	binary.BigEndian.PutUint16(queryPkt[4:6], uint16(8+len(dnsQuery)))
	queryPkt[6] = 17 // UDP
	queryPkt[7] = 64
	copy(queryPkt[8:24], srcIP)
	copy(queryPkt[24:40], dstIP)
	binary.BigEndian.PutUint16(queryPkt[40:42], srcPort)
	binary.BigEndian.PutUint16(queryPkt[42:44], dstPort)
	binary.BigEndian.PutUint16(queryPkt[44:46], uint16(8+len(dnsQuery)))
	copy(queryPkt[48:], dnsQuery)

	dnsResponse := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x07, 'd', 'i', 's', 'c', 'o', 'r', 'd', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		162, 159, 137, 232,
	}

	respPkt, err := SynthesizeDNSResponseIPv6UDPPacket(queryPkt, dnsResponse)
	if err != nil {
		t.Fatalf("SynthesizeDNSResponseIPv6UDPPacket failed: %v", err)
	}

	expectedTotalLen := 40 + 8 + len(dnsResponse)
	if len(respPkt) != expectedTotalLen {
		t.Fatalf("expected length %d, got %d", expectedTotalLen, len(respPkt))
	}

	// 1. Check IPv6 Header
	if respPkt[0]>>4 != 6 {
		t.Errorf("expected IPv6 version 6, got %d", respPkt[0]>>4)
	}
	payloadLen := binary.BigEndian.Uint16(respPkt[4:6])
	if int(payloadLen) != 8+len(dnsResponse) {
		t.Errorf("expected IPv6 payload length %d, got %d", 8+len(dnsResponse), payloadLen)
	}
	if respPkt[6] != 17 {
		t.Errorf("expected NextHeader = 17 (UDP), got %d", respPkt[6])
	}
	if !net.IP(respPkt[8:24]).Equal(dstIP) {
		t.Errorf("expected IPv6 SrcIP = %s, got %s", dstIP, net.IP(respPkt[8:24]))
	}
	if !net.IP(respPkt[24:40]).Equal(srcIP) {
		t.Errorf("expected IPv6 DstIP = %s, got %s", srcIP, net.IP(respPkt[24:40]))
	}

	// 2. Check UDP Header
	respSrcPort := binary.BigEndian.Uint16(respPkt[40:42])
	respDstPort := binary.BigEndian.Uint16(respPkt[42:44])
	if respSrcPort != dstPort {
		t.Errorf("expected UDP SrcPort = %d, got %d", dstPort, respSrcPort)
	}
	if respDstPort != srcPort {
		t.Errorf("expected UDP DstPort = %d, got %d", srcPort, respDstPort)
	}
	respUDPLen := binary.BigEndian.Uint16(respPkt[44:46])
	if int(respUDPLen) != 8+len(dnsResponse) {
		t.Errorf("expected UDP length %d, got %d", 8+len(dnsResponse), respUDPLen)
	}

	// 3. Check UDP Checksum
	chksum := binary.BigEndian.Uint16(respPkt[46:48])
	if chksum == 0 {
		t.Errorf("IPv6 UDP checksum must not be 0 per RFC 8200")
	}

	expectedCS, err := IPv6UDPChecksum(respPkt[8:24], respPkt[24:40], respSrcPort, respDstPort, dnsResponse)
	if err != nil {
		t.Fatalf("IPv6UDPChecksum failed: %v", err)
	}
	if chksum != expectedCS {
		t.Errorf("checksum mismatch: got 0x%04x, want 0x%04x", chksum, expectedCS)
	}

	// 4. Check Payload
	if string(respPkt[48:]) != string(dnsResponse) {
		t.Errorf("response payload mismatch")
	}
}

func TestSynthesizeDNSResponseIPv6UDPPacket_WithHopByHopOption(t *testing.T) {
	// Build an IPv6 packet with Hop-by-Hop options header (NextHeader=0, length=8 bytes)
	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:4860:4860::8844").To16()
	dnsQuery := []byte{0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	hbhLen := 8
	queryLen := 40 + hbhLen + 8 + len(dnsQuery)
	pkt := make([]byte, queryLen)
	pkt[0] = 0x60
	pkt[6] = 0 // Hop-by-Hop options
	copy(pkt[8:24], srcIP)
	copy(pkt[24:40], dstIP)

	// Hop-by-Hop Header at offset 40
	pkt[40] = 17 // Next header after HBH is UDP (17)
	pkt[41] = 0  // Length in 8-octet units minus 1 -> 0 means 8 bytes total

	// UDP header at offset 48
	binary.BigEndian.PutUint16(pkt[48:50], 12345)
	binary.BigEndian.PutUint16(pkt[50:52], 53)
	binary.BigEndian.PutUint16(pkt[52:54], uint16(8+len(dnsQuery)))
	copy(pkt[56:], dnsQuery)

	dnsResponse := []byte{0xaa, 0xbb, 0x81, 0x80}

	resp, err := SynthesizeDNSResponseIPv6UDPPacket(pkt, dnsResponse)
	if err != nil {
		t.Fatalf("expected successful synthesis through HBH extension header, got %v", err)
	}
	if len(resp) != 40+8+len(dnsResponse) {
		t.Fatalf("unexpected synthesized length: %d", len(resp))
	}
	if binary.BigEndian.Uint16(resp[40:42]) != 53 {
		t.Errorf("expected SrcPort 53, got %d", binary.BigEndian.Uint16(resp[40:42]))
	}
	if binary.BigEndian.Uint16(resp[42:44]) != 12345 {
		t.Errorf("expected DstPort 12345, got %d", binary.BigEndian.Uint16(resp[42:44]))
	}
}

func TestSynthesizeDNSResponseIPv6UDPPacket_Errors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := SynthesizeDNSResponseIPv6UDPPacket([]byte{0x60, 0x00}, []byte{0x01})
		if err == nil {
			t.Fatal("expected error for short packet")
		}
	})

	t.Run("not IPv6", func(t *testing.T) {
		pkt := make([]byte, 48)
		pkt[0] = 0x45 // IPv4
		_, err := SynthesizeDNSResponseIPv6UDPPacket(pkt, []byte{0x01})
		if err == nil {
			t.Fatal("expected error for IPv4 packet")
		}
	})

	t.Run("not UDP", func(t *testing.T) {
		pkt := make([]byte, 48)
		pkt[0] = 0x60
		pkt[6] = 6 // TCP
		_, err := SynthesizeDNSResponseIPv6UDPPacket(pkt, []byte{0x01})
		if err == nil {
			t.Fatal("expected error for non-UDP packet")
		}
	})
}

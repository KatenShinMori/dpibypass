package packetlab

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildMockUDP53QueryPacket(srcIP, dstIP [4]byte, srcPort uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = IPv4ProtoUDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	var ipSum uint32
	for i := 0; i < 20; i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for (ipSum >> 16) > 0 {
		ipSum = (ipSum & 0xFFFF) + (ipSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(ipSum))

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], 53)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	// Payload
	copy(pkt[28:], payload)

	return pkt
}

func TestSynthesizeDNSResponseIPv4UDPPacket(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(54321)
	queryPayload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	queryPacket := buildMockUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryPayload)

	t.Run("valid synthesis and checksum verification", func(t *testing.T) {
		dnsResponse := []byte{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x07, 'd', 'i', 's', 'c', 'o', 'r', 'd', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01, // Question
			0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
			162, 159, 130, 233, // Answer
		}

		respPkt, err := SynthesizeDNSResponseIPv4UDPPacket(queryPacket, dnsResponse)
		if err != nil {
			t.Fatalf("SynthesizeDNSResponseIPv4UDPPacket failed: %v", err)
		}

		// 1. Verify 4-tuple swapped
		respSrcIP := net.IP(respPkt[12:16])
		respDstIP := net.IP(respPkt[16:20])
		respSrcPort := binary.BigEndian.Uint16(respPkt[20:22])
		respDstPort := binary.BigEndian.Uint16(respPkt[22:24])

		if !respSrcIP.Equal(net.IP(dnsServerIP[:])) {
			t.Errorf("expected resp SrcIP %v, got %v", dnsServerIP, respSrcIP)
		}
		if !respDstIP.Equal(net.IP(clientIP[:])) {
			t.Errorf("expected resp DstIP %v, got %v", clientIP, respDstIP)
		}
		if respSrcPort != 53 {
			t.Errorf("expected resp SrcPort 53, got %d", respSrcPort)
		}
		if respDstPort != clientPort {
			t.Errorf("expected resp DstPort %d, got %d", clientPort, respDstPort)
		}

		// 2. Verify IPv4 Checksum
		validIPChk, err := VerifyIPv4Checksum(respPkt)
		if err != nil || !validIPChk {
			t.Errorf("IPv4 checksum invalid: valid=%v, err=%v", validIPChk, err)
		}

		// 3. Verify UDP Checksum is non-zero and valid RFC 768
		udpChk := binary.BigEndian.Uint16(respPkt[26:28])
		if udpChk == 0 {
			t.Errorf("expected non-zero RFC 768 UDP checksum in bytes [26:28], got 0x0000")
		}
		validUDPChk, err := VerifyUDPChecksum(respPkt)
		if err != nil || !validUDPChk {
			t.Errorf("UDP checksum invalid: valid=%v, err=%v", validUDPChk, err)
		}

		// 4. Verify Payload Preserved
		respPayload := respPkt[28:]
		if string(respPayload) != string(dnsResponse) {
			t.Error("DNS response payload mismatch")
		}
	})

	t.Run("odd length payload checksum verification", func(t *testing.T) {
		oddResponse := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00} // 11 bytes (odd)
		respPkt, err := SynthesizeDNSResponseIPv4UDPPacket(queryPacket, oddResponse)
		if err != nil {
			t.Fatalf("failed to synthesize odd payload packet: %v", err)
		}

		validUDPChk, err := VerifyUDPChecksum(respPkt)
		if err != nil || !validUDPChk {
			t.Errorf("UDP checksum invalid for odd payload: valid=%v, err=%v", validUDPChk, err)
		}
	})

	t.Run("zero UDP checksum folds to 0xFFFF per RFC 768", func(t *testing.T) {
		// Compute a 2-byte payload that forces the 16-bit one's complement UDP sum to 0xFFFF
		// so ^uint16(sum) == 0x0000, which RFC 768 requires transmitting as 0xFFFF.
		udpLen := uint16(MinUDPHeaderLen + 2)
		var sum uint32
		sum += uint32(binary.BigEndian.Uint16(dnsServerIP[0:2]))
		sum += uint32(binary.BigEndian.Uint16(dnsServerIP[2:4]))
		sum += uint32(binary.BigEndian.Uint16(clientIP[0:2]))
		sum += uint32(binary.BigEndian.Uint16(clientIP[2:4]))
		sum += uint32(IPv4ProtoUDP)
		sum += uint32(udpLen)
		sum += uint32(53)
		sum += uint32(clientPort)
		sum += uint32(udpLen)
		for (sum >> 16) > 0 {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
		complementWord := ^uint16(sum)
		var zeroSumPayload [2]byte
		binary.BigEndian.PutUint16(zeroSumPayload[:], complementWord)

		respPkt, err := SynthesizeDNSResponseIPv4UDPPacket(queryPacket, zeroSumPayload[:])
		if err != nil {
			t.Fatalf("SynthesizeDNSResponseIPv4UDPPacket failed: %v", err)
		}
		udpChk := binary.BigEndian.Uint16(respPkt[26:28])
		if udpChk != 0xFFFF {
			t.Errorf("expected 0x0000 UDP checksum to fold to 0xFFFF, got 0x%04X", udpChk)
		}
		validUDPChk, err := VerifyUDPChecksum(respPkt)
		if err != nil || !validUDPChk {
			t.Errorf("VerifyUDPChecksum failed on 0xFFFF folded checksum: valid=%v, err=%v", validUDPChk, err)
		}
	})

	t.Run("corrupt UDP checksum detection", func(t *testing.T) {
		dnsResponse := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		respPkt, err := SynthesizeDNSResponseIPv4UDPPacket(queryPacket, dnsResponse)
		if err != nil {
			t.Fatalf("SynthesizeDNSResponseIPv4UDPPacket failed: %v", err)
		}

		// Corrupt a byte in the payload
		respPkt[28] ^= 0xFF
		validUDPChk, _ := VerifyUDPChecksum(respPkt)
		if validUDPChk {
			t.Error("expected VerifyUDPChecksum to fail on corrupted packet, but it passed")
		}
	})

	t.Run("reject non-UDP packet", func(t *testing.T) {
		tcpPacket := make([]byte, 40)
		tcpPacket[0] = 0x45
		tcpPacket[9] = IPv4ProtoTCP
		binary.BigEndian.PutUint16(tcpPacket[2:4], 40)
		_, err := SynthesizeDNSResponseIPv4UDPPacket(tcpPacket, []byte("dns"))
		if err == nil {
			t.Error("expected error when passing non-UDP packet to UDP synthesizer")
		}
	})

	t.Run("reject truncated packet", func(t *testing.T) {
		_, err := SynthesizeDNSResponseIPv4UDPPacket([]byte{0x45, 0x00}, []byte("dns"))
		if err == nil {
			t.Error("expected error for truncated query packet")
		}
	})
}

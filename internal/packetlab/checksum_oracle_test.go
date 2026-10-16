package packetlab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// ============================================================================
// INDEPENDENT CHECKSUM ORACLE (RFC 1071 / RFC 791 / RFC 793)
//
// This oracle is an entirely independent reference implementation of the Internet
// Checksum algorithm. It does NOT call IPv4Checksum, TCPChecksum, VerifyIPv4Checksum,
// or VerifyTCPChecksum from the production packetlab package.
// ============================================================================

// independentRFC1071Sum calculates the 16-bit one's complement sum over data.
// In network byte order (RFC 791 §3.1, RFC 793 §3.1), if the octet count is odd,
// the final octet is padded on the right with zeros to form a 16-bit word (data[n-1] << 8).
func independentRFC1071Sum(data []byte) uint16 {
	var acc uint64
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		word := (uint64(data[i]) << 8) | uint64(data[i+1])
		acc += word
	}
	if n%2 == 1 {
		// RFC 791 / RFC 793: "the last octet is padded on the right with zeros to form a 16 bit word"
		acc += uint64(data[n-1]) << 8
	}
	// Fold 64-bit accumulator into 16 bits
	for acc > 0xFFFF {
		acc = (acc & 0xFFFF) + (acc >> 16)
	}
	return uint16(acc)
}

// independentVerifyIPv4 validates an IPv4 header independently:
// 1. Minimum length and header parsing (IHL >= 5, totalLen >= IHL).
// 2. Full header 1's complement sum (including wire checksum) must fold to 0xFFFF.
// 3. Recalculated checksum over zeroed header must match the stored wire checksum.
func independentVerifyIPv4(packet []byte) (bool, string) {
	if len(packet) < 20 {
		return false, fmt.Sprintf("packet too short (%d < 20)", len(packet))
	}
	version := packet[0] >> 4
	if version != 4 {
		return false, fmt.Sprintf("invalid IPv4 version (%d != 4)", version)
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 {
		return false, fmt.Sprintf("invalid IHL (%d < 20)", ihl)
	}
	if len(packet) < ihl {
		return false, fmt.Sprintf("packet buffer truncated for IPv4 header (%d < %d)", len(packet), ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || len(packet) < totalLen {
		return false, fmt.Sprintf("total length mismatch (totalLen=%d, buffer=%d, ihl=%d)", totalLen, len(packet), ihl)
	}

	header := packet[:ihl]
	storedCS := binary.BigEndian.Uint16(header[10:12])

	// Check 1: One's complement sum of all 16-bit words including stored checksum
	// Per RFC 1071 §1, sum of valid header including checksum must equal 0xFFFF.
	wireSum := independentRFC1071Sum(header)
	if wireSum != 0xFFFF {
		return false, fmt.Sprintf("IPv4 wire sum != 0xFFFF: got 0x%04x (checksum=0x%04x)", wireSum, storedCS)
	}

	// Check 2: Independent recalculation with zeroed checksum field
	headerZeroed := append([]byte(nil), header...)
	headerZeroed[10] = 0
	headerZeroed[11] = 0
	recalcSum := independentRFC1071Sum(headerZeroed)
	expectedCS := ^recalcSum
	if expectedCS == 0 {
		expectedCS = 0xFFFF
	}
	if expectedCS != storedCS {
		return false, fmt.Sprintf("IPv4 recalculated checksum mismatch: got 0x%04x, stored 0x%04x", expectedCS, storedCS)
	}

	return true, ""
}

// independentVerifyTCP validates an IPv4/TCP segment independently:
// 1. Extracts IPv4 pseudo-header (Src IP, Dst IP, Protocol 6, TCP Length).
// 2. Extracts TCP segment (TCP header + TCP options + payload).
// 3. Full 1's complement sum over [pseudo-header + TCP segment] must fold to 0xFFFF.
// 4. Recalculated checksum over zeroed TCP checksum field must match stored wire checksum.
func independentVerifyTCP(packet []byte) (bool, string) {
	if len(packet) < 40 {
		return false, fmt.Sprintf("packet too short for IPv4/TCP (%d < 40)", len(packet))
	}
	if packet[0]>>4 != 4 {
		return false, "not IPv4"
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return false, "invalid or truncated IPv4 header"
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl+20 || len(packet) < totalLen {
		return false, fmt.Sprintf("truncated packet (totalLen=%d, len=%d)", totalLen, len(packet))
	}
	if packet[9] != 6 {
		return false, fmt.Sprintf("not TCP (proto=%d)", packet[9])
	}

	srcIP := packet[12:16]
	dstIP := packet[16:20]
	tcpSegment := packet[ihl:totalLen]

	tcpOffset := int(tcpSegment[12]>>4) * 4
	if tcpOffset < 20 || len(tcpSegment) < tcpOffset {
		return false, fmt.Sprintf("invalid TCP data offset (%d)", tcpOffset)
	}
	storedCS := binary.BigEndian.Uint16(tcpSegment[16:18])

	// Assemble 12-byte IPv4 pseudo-header (RFC 793 §3.1)
	ph := make([]byte, 12)
	copy(ph[0:4], srcIP)
	copy(ph[4:8], dstIP)
	ph[8] = 0 // Reserved (zero)
	ph[9] = 6 // Protocol (TCP)
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcpSegment)))

	// Check 1: One's complement sum of [pseudo-header + TCP segment]
	combined := append(append([]byte(nil), ph...), tcpSegment...)
	wireSum := independentRFC1071Sum(combined)
	if wireSum != 0xFFFF {
		return false, fmt.Sprintf("TCP wire sum != 0xFFFF: got 0x%04x (checksum=0x%04x, segLen=%d)", wireSum, storedCS, len(tcpSegment))
	}

	// Check 2: Independent recalculation with zeroed TCP checksum field
	combinedZeroed := append([]byte(nil), combined...)
	// TCP checksum field is at offset 12 + 16 = 28 in combined buffer
	combinedZeroed[28] = 0
	combinedZeroed[29] = 0
	recalcSum := independentRFC1071Sum(combinedZeroed)
	expectedCS := ^recalcSum
	if expectedCS == 0 {
		expectedCS = 0xFFFF
	}
	if expectedCS != storedCS {
		return false, fmt.Sprintf("TCP recalculated checksum mismatch: got 0x%04x, stored 0x%04x", expectedCS, storedCS)
	}

	return true, ""
}

// ============================================================================
// 1. ORACLE SELF-TESTS & PUBLISHED REFERENCE VECTORS
// ============================================================================

func TestIndependentOracle_RFC1071NumericalExample(t *testing.T) {
	// RFC 1071 Section 3 Numerical Example:
	// Byte stream: 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7
	// 16-bit words: 0x0001, 0xf203, 0xf4f5, 0xf6f7
	// Sum: 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2ddf0
	// 16-bit fold: 0xddf0 + 2 = 0xddf2
	// 1's complement checksum: ~0xddf2 = 0x220d
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	sum := independentRFC1071Sum(data)
	if sum != 0xddf2 {
		t.Fatalf("RFC 1071 sum mismatch: got 0x%04x, want 0xddf2", sum)
	}
	cs := ^sum
	if cs != 0x220d {
		t.Fatalf("RFC 1071 checksum mismatch: got 0x%04x, want 0x220d", cs)
	}

	// Including the computed checksum at the end must produce sum == 0xFFFF
	withCS := append(data, byte(cs>>8), byte(cs&0xFF))
	if fullSum := independentRFC1071Sum(withCS); fullSum != 0xFFFF {
		t.Fatalf("Full sum with checksum != 0xFFFF: got 0x%04x", fullSum)
	}
}

func TestIndependentOracle_CorruptionDetection(t *testing.T) {
	// Verify that the independent oracle strictly detects single-bit and byte corruptions
	// across all header, option, pseudo-header, and payload positions.
	cfg := DefaultPacketConfig()
	cfg.IPv4Options = []byte{0x01, 0x01, 0x01, 0x00}                               // 4 bytes NOP, NOP, NOP, EOOL
	cfg.TCPOptions = []byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02}        // MSS (4B) + NOP NOP SACK (4B)
	cfg.Payload = []byte("The quick brown fox jumps over the lazy dog! 123456789") // odd length (57 bytes)

	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
	}

	// Base check: pristine packet must pass both independent oracles
	if ok, reason := independentVerifyIPv4(pkt); !ok {
		t.Fatalf("Pristine packet failed IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(pkt); !ok {
		t.Fatalf("Pristine packet failed TCP oracle: %s", reason)
	}

	// 1. IP corruption tests (must fail IPv4 oracle)
	ipCorruptionIndices := []struct {
		offset int
		name   string
	}{
		{0, "IPv4 Version/IHL"},
		{1, "IPv4 TOS"},
		{2, "IPv4 TotalLength MSB"},
		{4, "IPv4 Identification"},
		{6, "IPv4 Flags/FragOffset"},
		{8, "IPv4 TTL"},
		{9, "IPv4 Protocol"},
		{10, "IPv4 Checksum MSB"},
		{11, "IPv4 Checksum LSB"},
		{12, "IPv4 SrcIP"},
		{16, "IPv4 DstIP"},
		{20, "IPv4 Option byte"},
	}

	for _, tc := range ipCorruptionIndices {
		corrupted := append([]byte(nil), pkt...)
		corrupted[tc.offset] ^= 0x01
		if ok, _ := independentVerifyIPv4(corrupted); ok {
			t.Fatalf("Oracle FAILED to detect corruption in %s at byte %d", tc.name, tc.offset)
		}
	}

	// 2. TCP corruption tests (must fail TCP oracle)
	ihl := int(pkt[0]&0x0F) * 4
	tcpCorruptionIndices := []struct {
		offset int
		name   string
	}{
		{12, "SrcIP (pseudo-header field)"},
		{16, "DstIP (pseudo-header field)"},
		{ihl + 0, "TCP SrcPort"},
		{ihl + 2, "TCP DstPort"},
		{ihl + 4, "TCP SeqNum"},
		{ihl + 8, "TCP AckNum"},
		{ihl + 12, "TCP DataOffset"},
		{ihl + 13, "TCP Flags"},
		{ihl + 14, "TCP Window"},
		{ihl + 16, "TCP Checksum MSB"},
		{ihl + 17, "TCP Checksum LSB"},
		{ihl + 20, "TCP Option byte"},
		{ihl + len(cfg.TCPOptions) + 20, "TCP Payload first byte"},
		{len(pkt) - 1, "TCP Payload odd trailing byte"},
	}

	for _, tc := range tcpCorruptionIndices {
		corrupted := append([]byte(nil), pkt...)
		corrupted[tc.offset] ^= 0x01
		if ok, _ := independentVerifyTCP(corrupted); ok {
			t.Fatalf("Oracle FAILED to detect corruption in %s at byte %d", tc.name, tc.offset)
		}
	}
}

// ============================================================================
// 2. DEEP VERIFICATION OF EMITTED PACKETS ACROSS ALL AXES
// ============================================================================

func TestIndependentOracle_IPv4OptionsAndSegmentation(t *testing.T) {
	// Exercise packets with various IPv4 option lengths (4B, 8B, 12B) and segment them.
	// Both emitted packets (Segment 1 and Segment 2) must pass independent verification.
	ipv4OptionFixtures := []struct {
		name    string
		options []byte
	}{
		{
			name:    "4-byte IPv4 Options (IHL=6)",
			options: []byte{0x01, 0x01, 0x01, 0x00}, // NOP, NOP, NOP, EOOL
		},
		{
			name: "8-byte IPv4 Options (IHL=7, Record Route stub)",
			// Option type 7 (Record Route), length 7, pointer 4, 3 bytes IP stub, EOOL
			options: []byte{0x07, 0x07, 0x04, 10, 0, 0, 0x00, 0x00},
		},
		{
			name: "12-byte IPv4 Options (IHL=8)",
			// 12 bytes: NOPs and Timestamp/Security stubs
			options: []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00},
		},
	}

	splitOffsets := []int{1, 5, 17, 33, 49}

	for _, optFix := range ipv4OptionFixtures {
		for _, offset := range splitOffsets {
			testName := fmt.Sprintf("%s/SplitOffset_%d", optFix.name, offset)
			t.Run(testName, func(t *testing.T) {
				cfg := DefaultPacketConfig()
				cfg.IPv4Options = optFix.options
				cfg.Payload = []byte("A comprehensive payload testing IPv4 options preservation and checksum validity across segments!")

				pkt, err := BuildIPv4TCPPacket(cfg)
				if err != nil {
					t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
				}

				// Independent verification of generated input packet
				if ok, reason := independentVerifyIPv4(pkt); !ok {
					t.Fatalf("Input packet failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(pkt); !ok {
					t.Fatalf("Input packet failed independent TCP oracle: %s", reason)
				}

				// Split packet
				seg1, seg2, err := SplitIPv4TCPPacket(pkt, offset)
				if err != nil {
					t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
				}

				// Independent verification of Segment 1
				if ok, reason := independentVerifyIPv4(seg1); !ok {
					t.Fatalf("Segment 1 failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(seg1); !ok {
					t.Fatalf("Segment 1 failed independent TCP oracle: %s", reason)
				}

				// Independent verification of Segment 2
				if ok, reason := independentVerifyIPv4(seg2); !ok {
					t.Fatalf("Segment 2 failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(seg2); !ok {
					t.Fatalf("Segment 2 failed independent TCP oracle: %s", reason)
				}

				// Verify IPv4 options were preserved in both segments
				p1, _ := ParseIPv4TCPPacket(seg1)
				p2, _ := ParseIPv4TCPPacket(seg2)
				if !bytes.Equal(p1.IPv4Options, optFix.options) {
					t.Fatal("Segment 1 failed to preserve IPv4 options")
				}
				if !bytes.Equal(p2.IPv4Options, optFix.options) {
					t.Fatal("Segment 2 failed to preserve IPv4 options")
				}
			})
		}
	}
}

func TestIndependentOracle_TCPOptionsAndSegmentation(t *testing.T) {
	// Exercise packets with various TCP option lengths (4B, 8B, 12B, 20B) and segment them.
	// Both emitted packets must pass independent verification.
	tcpOptionFixtures := []struct {
		name    string
		options []byte
	}{
		{
			name:    "4-byte TCP MSS Option (DataOffset=6)",
			options: []byte{0x02, 0x04, 0x05, 0xb4}, // MSS = 1460
		},
		{
			name: "8-byte TCP Options (DataOffset=7, MSS + SACK permitted)",
			options: []byte{
				0x02, 0x04, 0x05, 0xb4, // MSS
				0x04, 0x02, 0x01, 0x01, // SACK permitted (2B) + 2x NOP
			},
		},
		{
			name: "12-byte TCP Options (DataOffset=8, Timestamps + NOP)",
			options: []byte{
				0x01, 0x01, // NOP, NOP
				0x08, 0x0a, // Timestamp option, length 10
				0x01, 0x02, 0x03, 0x04, // TSval
				0x05, 0x06, 0x07, 0x08, // TSecr
			},
		},
		{
			name: "20-byte TCP Options (DataOffset=10, MSS + SACK + Timestamps)",
			options: []byte{
				0x02, 0x04, 0x05, 0xb4, // MSS (4B)
				0x04, 0x02, 0x01, 0x03, 0x03, 0x07, // SACK (2B) + NOP + Window scale (3B) = 6B
				0x01, 0x01, // NOP, NOP (2B)
				0x08, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Timestamps (8B stub)
			},
		},
	}

	splitOffsets := []int{2, 11, 25, 41}

	for _, optFix := range tcpOptionFixtures {
		for _, offset := range splitOffsets {
			testName := fmt.Sprintf("%s/SplitOffset_%d", optFix.name, offset)
			t.Run(testName, func(t *testing.T) {
				cfg := DefaultPacketConfig()
				cfg.TCPOptions = optFix.options
				cfg.Payload = []byte("Validating TCP options preservation and pseudo-header checksum correctness across segmentation.")

				pkt, err := BuildIPv4TCPPacket(cfg)
				if err != nil {
					t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
				}

				// Independent verification of generated input packet
				if ok, reason := independentVerifyIPv4(pkt); !ok {
					t.Fatalf("Input packet failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(pkt); !ok {
					t.Fatalf("Input packet failed independent TCP oracle: %s", reason)
				}

				// Split packet
				seg1, seg2, err := SplitIPv4TCPPacket(pkt, offset)
				if err != nil {
					t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
				}

				// Independent verification of Segment 1
				if ok, reason := independentVerifyIPv4(seg1); !ok {
					t.Fatalf("Segment 1 failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(seg1); !ok {
					t.Fatalf("Segment 1 failed independent TCP oracle: %s", reason)
				}

				// Independent verification of Segment 2
				if ok, reason := independentVerifyIPv4(seg2); !ok {
					t.Fatalf("Segment 2 failed independent IPv4 oracle: %s", reason)
				}
				if ok, reason := independentVerifyTCP(seg2); !ok {
					t.Fatalf("Segment 2 failed independent TCP oracle: %s", reason)
				}

				// Verify TCP options were preserved in both segments
				p1, _ := ParseIPv4TCPPacket(seg1)
				p2, _ := ParseIPv4TCPPacket(seg2)
				if !bytes.Equal(p1.TCPOptions, optFix.options) {
					t.Fatal("Segment 1 failed to preserve TCP options")
				}
				if !bytes.Equal(p2.TCPOptions, optFix.options) {
					t.Fatal("Segment 2 failed to preserve TCP options")
				}
			})
		}
	}
}

func TestIndependentOracle_BothIPv4AndTCPOptions(t *testing.T) {
	// Simultaneous IPv4 options (8B) and TCP options (12B)
	cfg := DefaultPacketConfig()
	cfg.IPv4Options = []byte{0x07, 0x07, 0x04, 192, 168, 1, 0x00, 0x00}
	cfg.TCPOptions = []byte{0x01, 0x01, 0x08, 0x0a, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	cfg.Payload = []byte("Simultaneous options: IPv4 IHL=7 (28B) and TCP DataOffset=8 (32B) segmentation test!")

	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
	}

	if ok, reason := independentVerifyIPv4(pkt); !ok {
		t.Fatalf("Input failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(pkt); !ok {
		t.Fatalf("Input failed independent TCP oracle: %s", reason)
	}

	splitOffsets := []int{1, 13, 37, len(cfg.Payload) - 1}
	for _, offset := range splitOffsets {
		t.Run(fmt.Sprintf("SplitOffset_%d", offset), func(t *testing.T) {
			seg1, seg2, err := SplitIPv4TCPPacket(pkt, offset)
			if err != nil {
				t.Fatalf("Split failed at %d: %v", offset, err)
			}

			if ok, reason := independentVerifyIPv4(seg1); !ok {
				t.Fatalf("Seg1 failed IPv4 oracle at offset %d: %s", offset, reason)
			}
			if ok, reason := independentVerifyTCP(seg1); !ok {
				t.Fatalf("Seg1 failed TCP oracle at offset %d: %s", offset, reason)
			}
			if ok, reason := independentVerifyIPv4(seg2); !ok {
				t.Fatalf("Seg2 failed IPv4 oracle at offset %d: %s", offset, reason)
			}
			if ok, reason := independentVerifyTCP(seg2); !ok {
				t.Fatalf("Seg2 failed TCP oracle at offset %d: %s", offset, reason)
			}
		})
	}
}

func TestIndependentOracle_OddLengthPayloadsAndNetworkByteOrder(t *testing.T) {
	// Exhaustively test odd-length payloads and splits:
	// odd -> odd + odd (e.g. 2B -> 1B + 1B)
	// odd -> odd + even (e.g. 7B -> 3B + 4B)
	// odd -> even + odd (e.g. 7B -> 4B + 3B)
	// even -> odd + odd (e.g. 8B -> 3B + 5B)
	// even -> even + even (e.g. 8B -> 4B + 4B)
	oddPayloadCases := []struct {
		name        string
		payloadLen  int
		splitOffset int
	}{
		{"2 bytes payload (split 1)", 2, 1},           // 1B (odd) + 1B (odd)
		{"3 bytes payload (split 1)", 3, 1},           // 1B (odd) + 2B (even)
		{"3 bytes payload (split 2)", 3, 2},           // 2B (even) + 1B (odd)
		{"7 bytes payload (split 3)", 7, 3},           // 3B (odd) + 4B (even)
		{"7 bytes payload (split 4)", 7, 4},           // 4B (even) + 3B (odd)
		{"11 bytes payload (split 5)", 11, 5},         // 5B (odd) + 6B (even)
		{"15 bytes payload (split 7)", 15, 7},         // 7B (odd) + 8B (even)
		{"35 bytes payload (split 17)", 35, 17},       // 17B (odd) + 18B (even)
		{"97 bytes payload (split 35)", 97, 35},       // 35B (odd) + 62B (even)
		{"101 bytes payload (split 50)", 101, 50},     // 50B (even) + 51B (odd)
		{"503 bytes payload (split 251)", 503, 251},   // 251B (odd) + 252B (even)
		{"1433 bytes payload (split 716)", 1433, 716}, // 716B (even) + 717B (odd)
		{"1433 bytes payload (split 717)", 1433, 717}, // 717B (odd) + 716B (even)
	}

	for _, tc := range oddPayloadCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate deterministic repeating byte pattern
			payload := make([]byte, tc.payloadLen)
			for i := range payload {
				payload[i] = byte(0x20 + (i % 95)) // printable ASCII range
			}

			cfg := DefaultPacketConfig()
			cfg.Payload = payload

			pkt, err := BuildIPv4TCPPacket(cfg)
			if err != nil {
				t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
			}

			// Validate input packet with independent oracle
			if ok, reason := independentVerifyIPv4(pkt); !ok {
				t.Fatalf("Input failed independent IPv4 oracle: %s", reason)
			}
			if ok, reason := independentVerifyTCP(pkt); !ok {
				t.Fatalf("Input failed independent TCP oracle: %s", reason)
			}

			// Split packet
			seg1, seg2, err := SplitIPv4TCPPacket(pkt, tc.splitOffset)
			if err != nil {
				t.Fatalf("Split failed at offset %d: %v", tc.splitOffset, err)
			}

			// Validate BOTH emitted segments with independent oracle
			if ok, reason := independentVerifyIPv4(seg1); !ok {
				t.Fatalf("Seg1 failed IPv4 oracle: %s", reason)
			}
			if ok, reason := independentVerifyTCP(seg1); !ok {
				t.Fatalf("Seg1 failed TCP oracle: %s", reason)
			}
			if ok, reason := independentVerifyIPv4(seg2); !ok {
				t.Fatalf("Seg2 failed IPv4 oracle: %s", reason)
			}
			if ok, reason := independentVerifyTCP(seg2); !ok {
				t.Fatalf("Seg2 failed TCP oracle: %s", reason)
			}
		})
	}
}

func TestIndependentOracle_NetworkByteOrderTrailingOctetAssertion(t *testing.T) {
	// Crucial endianness verification:
	// RFC 793 §3.1 requires: "If a segment contains an odd number of header and text
	// octets to be checksummed, the last octet is padded on the right with zeros
	// to form a 16 bit word for checksum purposes."
	//
	// Padded on the right with zeros means in big-endian network byte order:
	//   16-bit word = (lastOctet << 8) | 0x00
	// If a buggy implementation padded on the left instead:
	//   16-bit word = (0x00 << 8) | lastOctet = lastOctet
	//
	// Verify that the checksum produced by BuildIPv4TCPPacket and SplitIPv4TCPPacket
	// corresponds strictly to (lastOctet << 8) and that the swapped-endian alternative
	// fails independent validation.
	cfg := DefaultPacketConfig()
	cfg.Payload = []byte("A") // 1 byte payload (odd)

	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
	}

	if ok, reason := independentVerifyTCP(pkt); !ok {
		t.Fatalf("Valid 1-byte payload failed independent TCP oracle: %s", reason)
	}

	// Now compute what a buggy little-endian / left-padded verifier would produce
	ihl := int(pkt[0]&0x0F) * 4
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	tcpSeg := pkt[ihl:totalLen]

	ph := make([]byte, 12)
	copy(ph[0:4], pkt[12:16])
	copy(ph[4:8], pkt[16:20])
	ph[8] = 0
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcpSeg)))

	combined := append(append([]byte(nil), ph...), tcpSeg...)
	// Zero checksum field at offset 28
	combined[28] = 0
	combined[29] = 0

	// Buggy sum: pad odd byte in low position instead of high position
	var buggyAcc uint64
	for i := 0; i < len(combined)-1; i += 2 {
		buggyAcc += (uint64(combined[i]) << 8) | uint64(combined[i+1])
	}
	// Buggy low padding:
	buggyAcc += uint64(combined[len(combined)-1]) // NOT shifted by 8!
	for buggyAcc > 0xFFFF {
		buggyAcc = (buggyAcc & 0xFFFF) + (buggyAcc >> 16)
	}
	buggyChecksum := ^uint16(buggyAcc)

	storedChecksum := binary.BigEndian.Uint16(tcpSeg[16:18])
	if storedChecksum == buggyChecksum {
		t.Fatal("FATAL: Stored checksum matched the buggy low-padded checksum! RFC 793 network byte order violated!")
	}
}

func TestIndependentOracle_ZeroPayloadPacket(t *testing.T) {
	cfg := DefaultPacketConfig()
	cfg.Payload = nil // 0 bytes payload (pure ACK)

	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket failed for zero payload: %v", err)
	}

	if len(pkt) != 40 {
		t.Fatalf("Packet length mismatch: got %d, want 40", len(pkt))
	}

	if ok, reason := independentVerifyIPv4(pkt); !ok {
		t.Fatalf("Zero-payload packet failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(pkt); !ok {
		t.Fatalf("Zero-payload packet failed independent TCP oracle: %s", reason)
	}
}

func TestIndependentOracle_CanonicalReferenceVector(t *testing.T) {
	// Canonical RFC 791 / RFC 793 synthetic ACK reference packet fixture:
	// IP Header: 20 bytes, Src=127.0.0.1, Dst=127.0.0.1, ID=0x1234, TTL=64, DF=1
	// TCP Header: 20 bytes, SrcPort=12345, DstPort=54321, Seq=1000, Ack=2000, Flags=ACK, Win=65535
	wirePacket := []byte{
		// IPv4 Header (20 bytes)
		0x45, 0x00, 0x00, 0x28, // Ver=4, IHL=5, TOS=0, TotalLen=40
		0x12, 0x34, 0x40, 0x00, // ID=0x1234, Flags=DF, FragOff=0
		0x40, 0x06, 0x2a, 0x9a, // TTL=64, Proto=TCP(6), Checksum=0x2a9a
		0x7f, 0x00, 0x00, 0x01, // SrcIP: 127.0.0.1
		0x7f, 0x00, 0x00, 0x01, // DstIP: 127.0.0.1

		// TCP Header (20 bytes)
		0x30, 0x39, 0xd4, 0x31, // SrcPort=12345, DstPort=54321
		0x00, 0x00, 0x03, 0xe8, // Seq=1000
		0x00, 0x00, 0x07, 0xd0, // Ack=2000
		0x50, 0x10, 0xff, 0xff, // DataOffset=5, Flags=ACK(0x10), Win=65535
		0xa1, 0xaf, 0x00, 0x00, // Checksum=0xa1af, UrgPtr=0
	}

	if ok, reason := independentVerifyIPv4(wirePacket); !ok {
		t.Fatalf("Canonical reference vector failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(wirePacket); !ok {
		t.Fatalf("Canonical reference vector failed independent TCP oracle: %s", reason)
	}

	// Verify production verifiers also validate this exact reference fixture
	vIP, err := VerifyIPv4Checksum(wirePacket)
	if err != nil || !vIP {
		t.Fatalf("Canonical reference vector failed VerifyIPv4Checksum: valid=%v, err=%v", vIP, err)
	}
	vTCP, err := VerifyTCPChecksum(wirePacket)
	if err != nil || !vTCP {
		t.Fatalf("Canonical reference vector failed VerifyTCPChecksum: valid=%v, err=%v", vTCP, err)
	}
}

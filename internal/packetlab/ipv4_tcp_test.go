package packetlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"dpibypass/internal/tlsparse"
)

func TestSplitIPv4TCPPacket_BasicOddAndEven(t *testing.T) {
	testCases := []struct {
		name        string
		payload     []byte
		splitOffset int
	}{
		{
			name:        "Odd length payload split at odd offset",
			payload:     []byte("1234567"), // 7 bytes
			splitOffset: 3,                 // 3 and 4
		},
		{
			name:        "Odd length payload split at even offset",
			payload:     []byte("1234567"), // 7 bytes
			splitOffset: 4,                 // 4 and 3
		},
		{
			name:        "Even length payload split at even offset",
			payload:     []byte("12345678"), // 8 bytes
			splitOffset: 4,                  // 4 and 4
		},
		{
			name:        "Even length payload split at odd offset",
			payload:     []byte("12345678"), // 8 bytes
			splitOffset: 3,                  // 3 and 5
		},
		{
			name:        "Single byte first segment",
			payload:     []byte("abcdef"),
			splitOffset: 1,
		},
		{
			name:        "Single byte second segment",
			payload:     []byte("abcdef"),
			splitOffset: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultPacketConfig()
			cfg.Payload = tc.payload
			cfg.SeqNum = 50000
			cfg.AckNum = 90000
			cfg.Identification = 0x4321

			pkt, err := BuildIPv4TCPPacket(cfg)
			if err != nil {
				t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
			}

			// Capture original byte slice copy to prove input immutability
			pktCopy := append([]byte(nil), pkt...)

			first, second, err := SplitIPv4TCPPacket(pkt, tc.splitOffset)
			if err != nil {
				t.Fatalf("SplitIPv4TCPPacket returned error: %v", err)
			}

			// Assert input packet was not mutated
			if !bytes.Equal(pkt, pktCopy) {
				t.Fatal("SplitIPv4TCPPacket mutated the input packet buffer!")
			}

			// Validate segment 1
			p1, err := ParseIPv4TCPPacket(first)
			if err != nil {
				t.Fatalf("ParseIPv4TCPPacket(first) failed: %v", err)
			}
			if len(p1.Payload) != tc.splitOffset {
				t.Fatalf("Segment 1 payload len = %d, expected %d", len(p1.Payload), tc.splitOffset)
			}
			if p1.SeqNum != cfg.SeqNum {
				t.Fatalf("Segment 1 seq = %d, expected original %d", p1.SeqNum, cfg.SeqNum)
			}
			if (p1.TCPFlags & TCPFlagPSH) != 0 {
				t.Fatalf("Segment 1 must have PSH flag cleared, got flags=0x%02x", p1.TCPFlags)
			}
			if (p1.TCPFlags & TCPFlagACK) == 0 {
				t.Fatalf("Segment 1 must have ACK flag set, got flags=0x%02x", p1.TCPFlags)
			}
			if p1.Identification != cfg.Identification {
				t.Fatalf("Segment 1 identification = 0x%04x, expected 0x%04x", p1.Identification, cfg.Identification)
			}

			// Validate segment 2
			p2, err := ParseIPv4TCPPacket(second)
			if err != nil {
				t.Fatalf("ParseIPv4TCPPacket(second) failed: %v", err)
			}
			expectedSeg2Len := len(tc.payload) - tc.splitOffset
			if len(p2.Payload) != expectedSeg2Len {
				t.Fatalf("Segment 2 payload len = %d, expected %d", len(p2.Payload), expectedSeg2Len)
			}
			expectedSeg2Seq := cfg.SeqNum + uint32(tc.splitOffset)
			if p2.SeqNum != expectedSeg2Seq {
				t.Fatalf("Segment 2 seq = %d, expected %d", p2.SeqNum, expectedSeg2Seq)
			}
			if (p2.TCPFlags & TCPFlagPSH) == 0 {
				t.Fatalf("Segment 2 must preserve PSH flag, got flags=0x%02x", p2.TCPFlags)
			}
			if p2.Identification != cfg.Identification+1 {
				t.Fatalf("Segment 2 identification = 0x%04x, expected 0x%04x", p2.Identification, cfg.Identification+1)
			}

			// Payload concatenation test
			reconstructed := append(p1.Payload, p2.Payload...)
			if !bytes.Equal(reconstructed, tc.payload) {
				t.Fatalf("Reconstructed payload mismatch! Got %q, want %q", reconstructed, tc.payload)
			}
			hOrig := sha256.Sum256(tc.payload)
			hRecon := sha256.Sum256(reconstructed)
			if hOrig != hRecon {
				t.Fatalf("Payload SHA-256 hash mismatch! Got %x, want %x", hRecon, hOrig)
			}

			// Checksums verification (production verifiers)
			vIP1, err := VerifyIPv4Checksum(first)
			if err != nil || !vIP1 {
				t.Fatalf("Segment 1 IPv4 checksum invalid (valid=%v, err=%v)", vIP1, err)
			}
			vTCP1, err := VerifyTCPChecksum(first)
			if err != nil || !vTCP1 {
				t.Fatalf("Segment 1 TCP checksum invalid (valid=%v, err=%v)", vTCP1, err)
			}

			vIP2, err := VerifyIPv4Checksum(second)
			if err != nil || !vIP2 {
				t.Fatalf("Segment 2 IPv4 checksum invalid (valid=%v, err=%v)", vIP2, err)
			}
			vTCP2, err := VerifyTCPChecksum(second)
			if err != nil || !vTCP2 {
				t.Fatalf("Segment 2 TCP checksum invalid (valid=%v, err=%v)", vTCP2, err)
			}

			// Independent oracle verification (RFC 1071 / RFC 791 / RFC 793)
			if ok, reason := independentVerifyIPv4(first); !ok {
				t.Fatalf("Segment 1 failed independent IPv4 oracle: %s", reason)
			}
			if ok, reason := independentVerifyTCP(first); !ok {
				t.Fatalf("Segment 1 failed independent TCP oracle: %s", reason)
			}
			if ok, reason := independentVerifyIPv4(second); !ok {
				t.Fatalf("Segment 2 failed independent IPv4 oracle: %s", reason)
			}
			if ok, reason := independentVerifyTCP(second); !ok {
				t.Fatalf("Segment 2 failed independent TCP oracle: %s", reason)
			}
		})
	}
}

func TestSplitIPv4TCPPacket_SequenceNumberWraparound(t *testing.T) {
	// TCP sequence numbers wrap around modulo 2^32
	cfg := DefaultPacketConfig()
	cfg.SeqNum = 0xFFFFFFF0 // 16 bytes before 2^32 - 1
	cfg.Payload = bytes.Repeat([]byte("X"), 64)

	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
	}

	splitOffset := 32 // wraps across boundary: 0xFFFFFFF0 + 32 = 0x00000010
	first, second, err := SplitIPv4TCPPacket(pkt, splitOffset)
	if err != nil {
		t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
	}

	p1, err := ParseIPv4TCPPacket(first)
	if err != nil {
		t.Fatalf("ParseIPv4TCPPacket(first) failed: %v", err)
	}
	if p1.SeqNum != 0xFFFFFFF0 {
		t.Fatalf("Segment 1 seq = 0x%08x, expected 0xFFFFFFF0", p1.SeqNum)
	}

	p2, err := ParseIPv4TCPPacket(second)
	if err != nil {
		t.Fatalf("ParseIPv4TCPPacket(second) failed: %v", err)
	}
	expectedSeq2 := uint32(uint64(0xFFFFFFF0+32) & 0xFFFFFFFF)
	if expectedSeq2 != 0x00000010 {
		t.Fatalf("Sanity check failed: 0xFFFFFFF0 + 32 = 0x%08x", expectedSeq2)
	}
	if p2.SeqNum != expectedSeq2 {
		t.Fatalf("Segment 2 wrapped sequence number mismatch! Got 0x%08x, want 0x%08x", p2.SeqNum, expectedSeq2)
	}

	// Verify checksums remain valid after wrap (production verifiers)
	vTCP1, err := VerifyTCPChecksum(first)
	if err != nil || !vTCP1 {
		t.Fatalf("Segment 1 TCP checksum invalid after seq wrap: %v", err)
	}
	vTCP2, err := VerifyTCPChecksum(second)
	if err != nil || !vTCP2 {
		t.Fatalf("Segment 2 TCP checksum invalid after seq wrap: %v", err)
	}

	// Independent oracle verification
	if ok, reason := independentVerifyIPv4(first); !ok {
		t.Fatalf("Segment 1 failed IPv4 oracle after seq wrap: %s", reason)
	}
	if ok, reason := independentVerifyTCP(first); !ok {
		t.Fatalf("Segment 1 failed TCP oracle after seq wrap: %s", reason)
	}
	if ok, reason := independentVerifyIPv4(second); !ok {
		t.Fatalf("Segment 2 failed IPv4 oracle after seq wrap: %s", reason)
	}
	if ok, reason := independentVerifyTCP(second); !ok {
		t.Fatalf("Segment 2 failed TCP oracle after seq wrap: %s", reason)
	}
}

func TestSplitIPv4TCPPacket_OptionsPreservation(t *testing.T) {
	t.Run("IPv4 options present", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		// 4 bytes of IPv4 NOP options (0x01, 0x01, 0x01, 0x01)
		cfg.IPv4Options = []byte{0x01, 0x01, 0x01, 0x01}
		cfg.Payload = []byte("Payload with IP options")

		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
		}

		first, second, err := SplitIPv4TCPPacket(pkt, 10)
		if err != nil {
			t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
		}

		p1, err := ParseIPv4TCPPacket(first)
		if err != nil {
			t.Fatalf("Parse first segment failed: %v", err)
		}
		if p1.IHL != 24 {
			t.Fatalf("Segment 1 IHL = %d, expected 24", p1.IHL)
		}
		if !bytes.Equal(p1.IPv4Options, cfg.IPv4Options) {
			t.Fatalf("Segment 1 IPv4 options mismatch: got %x, want %x", p1.IPv4Options, cfg.IPv4Options)
		}

		p2, err := ParseIPv4TCPPacket(second)
		if err != nil {
			t.Fatalf("Parse second segment failed: %v", err)
		}
		if p2.IHL != 24 {
			t.Fatalf("Segment 2 IHL = %d, expected 24", p2.IHL)
		}
		if !bytes.Equal(p2.IPv4Options, cfg.IPv4Options) {
			t.Fatalf("Segment 2 IPv4 options mismatch: got %x, want %x", p2.IPv4Options, cfg.IPv4Options)
		}

		// Verify checksums (production verifiers)
		v1, _ := VerifyIPv4Checksum(first)
		v2, _ := VerifyIPv4Checksum(second)
		if !v1 || !v2 {
			t.Fatalf("IPv4 checksum invalid with IP options: seg1=%v, seg2=%v", v1, v2)
		}

		// Independent oracle verification
		if ok, reason := independentVerifyIPv4(first); !ok {
			t.Fatalf("Segment 1 failed IPv4 oracle with IP options: %s", reason)
		}
		if ok, reason := independentVerifyTCP(first); !ok {
			t.Fatalf("Segment 1 failed TCP oracle with IP options: %s", reason)
		}
		if ok, reason := independentVerifyIPv4(second); !ok {
			t.Fatalf("Segment 2 failed IPv4 oracle with IP options: %s", reason)
		}
		if ok, reason := independentVerifyTCP(second); !ok {
			t.Fatalf("Segment 2 failed TCP oracle with IP options: %s", reason)
		}
	})

	t.Run("TCP options present", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		// TCP Timestamp option (kind=8, len=10) padded to 12 bytes
		tcpOpts := []byte{
			0x08, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x01, // NOP, NOP padding
		}
		cfg.TCPOptions = tcpOpts
		cfg.Payload = []byte("Payload with TCP options")

		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
		}

		first, second, err := SplitIPv4TCPPacket(pkt, 8)
		if err != nil {
			t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
		}

		p1, err := ParseIPv4TCPPacket(first)
		if err != nil {
			t.Fatalf("Parse first segment failed: %v", err)
		}
		if p1.TCPDataOffset != 32 {
			t.Fatalf("Segment 1 TCP offset = %d, expected 32", p1.TCPDataOffset)
		}
		if !bytes.Equal(p1.TCPOptions, tcpOpts) {
			t.Fatalf("Segment 1 TCP options mismatch: got %x, want %x", p1.TCPOptions, tcpOpts)
		}

		p2, err := ParseIPv4TCPPacket(second)
		if err != nil {
			t.Fatalf("Parse second segment failed: %v", err)
		}
		if p2.TCPDataOffset != 32 {
			t.Fatalf("Segment 2 TCP offset = %d, expected 32", p2.TCPDataOffset)
		}
		if !bytes.Equal(p2.TCPOptions, tcpOpts) {
			t.Fatalf("Segment 2 TCP options mismatch: got %x, want %x", p2.TCPOptions, tcpOpts)
		}

		// Verify TCP checksums (production verifiers)
		v1, _ := VerifyTCPChecksum(first)
		v2, _ := VerifyTCPChecksum(second)
		if !v1 || !v2 {
			t.Fatalf("TCP checksum invalid with TCP options: seg1=%v, seg2=%v", v1, v2)
		}

		// Independent oracle verification
		if ok, reason := independentVerifyIPv4(first); !ok {
			t.Fatalf("Segment 1 failed IPv4 oracle with TCP options: %s", reason)
		}
		if ok, reason := independentVerifyTCP(first); !ok {
			t.Fatalf("Segment 1 failed TCP oracle with TCP options: %s", reason)
		}
		if ok, reason := independentVerifyIPv4(second); !ok {
			t.Fatalf("Segment 2 failed IPv4 oracle with TCP options: %s", reason)
		}
		if ok, reason := independentVerifyTCP(second); !ok {
			t.Fatalf("Segment 2 failed TCP oracle with TCP options: %s", reason)
		}
	})
}

func TestSplitIPv4TCPPacket_TCPFlagsPolicy(t *testing.T) {
	t.Run("ACK only original packet", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.TCPFlags = TCPFlagACK
		cfg.Payload = []byte("ACK only data packet")

		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
		}

		first, second, err := SplitIPv4TCPPacket(pkt, 5)
		if err != nil {
			t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
		}

		p1, _ := ParseIPv4TCPPacket(first)
		p2, _ := ParseIPv4TCPPacket(second)

		if p1.TCPFlags != TCPFlagACK {
			t.Fatalf("Segment 1 flags = 0x%02x, want ACK (0x10)", p1.TCPFlags)
		}
		if p2.TCPFlags != TCPFlagACK {
			t.Fatalf("Segment 2 flags = 0x%02x, want ACK (0x10)", p2.TCPFlags)
		}

		if ok, reason := independentVerifyIPv4(first); !ok {
			t.Fatalf("Segment 1 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(first); !ok {
			t.Fatalf("Segment 1 failed TCP oracle: %s", reason)
		}
		if ok, reason := independentVerifyIPv4(second); !ok {
			t.Fatalf("Segment 2 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(second); !ok {
			t.Fatalf("Segment 2 failed TCP oracle: %s", reason)
		}
	})

	t.Run("ACK|PSH original packet", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.TCPFlags = TCPFlagACK | TCPFlagPSH
		cfg.Payload = []byte("ACK and PSH data packet")

		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
		}

		first, second, err := SplitIPv4TCPPacket(pkt, 6)
		if err != nil {
			t.Fatalf("SplitIPv4TCPPacket failed: %v", err)
		}

		p1, _ := ParseIPv4TCPPacket(first)
		p2, _ := ParseIPv4TCPPacket(second)

		if p1.TCPFlags != TCPFlagACK {
			t.Fatalf("Segment 1 must have PSH cleared; got 0x%02x, want 0x10", p1.TCPFlags)
		}
		if p2.TCPFlags != (TCPFlagACK | TCPFlagPSH) {
			t.Fatalf("Segment 2 must preserve PSH; got 0x%02x, want 0x18", p2.TCPFlags)
		}

		if ok, reason := independentVerifyIPv4(first); !ok {
			t.Fatalf("Segment 1 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(first); !ok {
			t.Fatalf("Segment 1 failed TCP oracle: %s", reason)
		}
		if ok, reason := independentVerifyIPv4(second); !ok {
			t.Fatalf("Segment 2 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(second); !ok {
			t.Fatalf("Segment 2 failed TCP oracle: %s", reason)
		}
	})

	// Reject unsupported control flags
	unsupportedFlags := []struct {
		name string
		flag uint8
	}{
		{"SYN", TCPFlagSYN},
		{"FIN", TCPFlagFIN},
		{"RST", TCPFlagRST},
		{"URG", TCPFlagURG},
		{"ECE", TCPFlagECE},
		{"CWR", TCPFlagCWR},
		{"SYN+ACK", TCPFlagSYN | TCPFlagACK},
		{"FIN+ACK", TCPFlagFIN | TCPFlagACK},
		{"RST+ACK", TCPFlagRST | TCPFlagACK},
		{"URG+ACK", TCPFlagURG | TCPFlagACK},
	}

	for _, uf := range unsupportedFlags {
		t.Run("Reject_"+uf.name, func(t *testing.T) {
			cfg := DefaultPacketConfig()
			cfg.TCPFlags = uf.flag
			pkt, err := BuildIPv4TCPPacket(cfg)
			if err != nil {
				t.Fatalf("BuildIPv4TCPPacket failed: %v", err)
			}

			first, second, err := SplitIPv4TCPPacket(pkt, 5)
			if err == nil {
				t.Fatalf("SplitIPv4TCPPacket unexpectedly succeeded for unsupported flag %s (0x%02x)", uf.name, uf.flag)
			}
			if first != nil || second != nil {
				t.Fatalf("SplitIPv4TCPPacket must return nil segments on error")
			}
			if !errors.Is(err, ErrUnsupportedTCPFlags) && !errors.Is(err, ErrMissingACKFlag) {
				t.Fatalf("Expected ErrUnsupportedTCPFlags or ErrMissingACKFlag, got: %v", err)
			}
		})
	}
}

func TestSplitIPv4TCPPacket_RejectionOfInvalidPackets(t *testing.T) {
	t.Run("Nil and buffer too short", func(t *testing.T) {
		_, _, err := SplitIPv4TCPPacket(nil, 5)
		if !errors.Is(err, ErrPacketTooShort) {
			t.Fatalf("Expected ErrPacketTooShort, got: %v", err)
		}

		shortBuf := make([]byte, 39)
		_, _, err = SplitIPv4TCPPacket(shortBuf, 5)
		if !errors.Is(err, ErrPacketTooShort) {
			t.Fatalf("Expected ErrPacketTooShort for 39-byte buf, got: %v", err)
		}
	})

	t.Run("IPv6 packet rejected", func(t *testing.T) {
		buf := make([]byte, 60)
		buf[0] = 0x60 // IPv6 version 6
		_, _, err := SplitIPv4TCPPacket(buf, 5)
		if !errors.Is(err, ErrNotIPv4) {
			t.Fatalf("Expected ErrNotIPv4, got: %v", err)
		}
	})

	t.Run("Invalid IHL (< 5)", func(t *testing.T) {
		buf := make([]byte, 60)
		buf[0] = 0x44 // IPv4, IHL = 4 (invalid)
		_, _, err := SplitIPv4TCPPacket(buf, 5)
		if !errors.Is(err, ErrInvalidIHL) {
			t.Fatalf("Expected ErrInvalidIHL, got: %v", err)
		}
	})

	t.Run("Truncated IPv4 header", func(t *testing.T) {
		buf := make([]byte, 40)
		buf[0] = 0x4F // IPv4, IHL = 15 (60 bytes), but buffer is only 40
		_, _, err := SplitIPv4TCPPacket(buf, 5)
		if !errors.Is(err, ErrTruncatedIPv4Header) {
			t.Fatalf("Expected ErrTruncatedIPv4Header, got: %v", err)
		}
	})

	t.Run("Total length less than IHL", func(t *testing.T) {
		buf := make([]byte, 60)
		buf[0] = 0x45 // IPv4, IHL = 5 (20 bytes)
		binary.BigEndian.PutUint16(buf[2:4], 16)
		_, _, err := SplitIPv4TCPPacket(buf, 5)
		if !errors.Is(err, ErrInvalidTotalLength) {
			t.Fatalf("Expected ErrInvalidTotalLength, got: %v", err)
		}
	})

	t.Run("Truncated packet relative to Total Length", func(t *testing.T) {
		buf := make([]byte, 40)
		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:4], 100) // Claims 100, buffer is 40
		_, _, err := SplitIPv4TCPPacket(buf, 5)
		if !errors.Is(err, ErrTruncatedIPv4Packet) {
			t.Fatalf("Expected ErrTruncatedIPv4Packet, got: %v", err)
		}
	})

	t.Run("Non-TCP protocol (UDP)", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[9] = 17 // UDP
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrNotTCP) {
			t.Fatalf("Expected ErrNotTCP, got: %v", err)
		}
	})

	t.Run("IPv4 Reserved flag bit set", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[6] |= 0x80 // Bit 15 set
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrIPv4ReservedFlagSet) {
			t.Fatalf("Expected ErrIPv4ReservedFlagSet, got: %v", err)
		}
	})

	t.Run("IPv4 More Fragments (MF) set", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[6] |= 0x20 // Bit 13 set (MF)
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrIPv4Fragmented) {
			t.Fatalf("Expected ErrIPv4Fragmented, got: %v", err)
		}
	})

	t.Run("IPv4 Fragment Offset non-zero", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[7] = 0x01 // Offset > 0
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrIPv4Fragmented) {
			t.Fatalf("Expected ErrIPv4Fragmented, got: %v", err)
		}
	})

	t.Run("Invalid TCP Data Offset (< 5)", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[32] = 0x40 // TCP offset = 4 (16 bytes, invalid)
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrInvalidTCPDataOffset) {
			t.Fatalf("Expected ErrInvalidTCPDataOffset, got: %v", err)
		}
	})

	t.Run("Truncated TCP options", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = []byte("short") // 5 bytes: totalLen = 20 + 20 + 5 = 45, tcpLen = 25
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[32] = 0xF0 // TCP offset = 15 (60 bytes), but tcpLen is only 25
		_, _, err = SplitIPv4TCPPacket(pkt, 2)
		if !errors.Is(err, ErrTruncatedTCPOptions) {
			t.Fatalf("Expected ErrTruncatedTCPOptions, got: %v", err)
		}
	})

	t.Run("TCP Reserved bits or NS flag set", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[32] |= 0x01 // NS flag
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrTCPReservedBitsSet) {
			t.Fatalf("Expected ErrTCPReservedBitsSet, got: %v", err)
		}
	})

	t.Run("Missing ACK flag", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.TCPFlags = 0 // No flags
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = SplitIPv4TCPPacket(pkt, 5)
		if !errors.Is(err, ErrMissingACKFlag) {
			t.Fatalf("Expected ErrMissingACKFlag, got: %v", err)
		}
	})

	t.Run("Empty TCP payload", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = nil // No payload
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = SplitIPv4TCPPacket(pkt, 0)
		if !errors.Is(err, ErrEmptyTCPPayload) {
			t.Fatalf("Expected ErrEmptyTCPPayload, got: %v", err)
		}
	})

	t.Run("Out of bounds split offset", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = []byte("12345") // 5 bytes: valid offsets are 1..4
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}

		outOfBounds := []int{-1, 0, 5, 6, 100}
		for _, offset := range outOfBounds {
			_, _, err := SplitIPv4TCPPacket(pkt, offset)
			if !errors.Is(err, ErrSplitOffsetOutOfBounds) {
				t.Fatalf("Offset %d: expected ErrSplitOffsetOutOfBounds, got: %v", offset, err)
			}
		}
	})

	t.Run("Buffer longer than Total Length (inconsistent length fields)", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = []byte("12345")
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		// Append extra trailing bytes to the buffer
		padded := append(pkt, 0x00, 0x00, 0x00, 0x00)
		_, _, err = SplitIPv4TCPPacket(padded, 2)
		if !errors.Is(err, ErrInconsistentTotalLength) {
			t.Fatalf("Expected ErrInconsistentTotalLength for trailing buffer bytes, got: %v", err)
		}
	})

	t.Run("Payload too short to split into two nonempty parts (1 byte)", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = []byte("A") // 1 byte payload: cannot split into two nonempty parts
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = SplitIPv4TCPPacket(pkt, 1)
		if !errors.Is(err, ErrPayloadTooShort) {
			t.Fatalf("Expected ErrPayloadTooShort for 1-byte payload, got: %v", err)
		}
	})
}

func TestSplitIPv4TCPPacket_NoPanicsOnFuzzedInput(t *testing.T) {
	// Robustness check: pass random slices and arbitrary mutated bytes; must never panic.
	seeds := [][]byte{
		{},
		{0x45},
		{0x45, 0x00, 0x00},
		make([]byte, 40),
		make([]byte, 100),
		bytes.Repeat([]byte{0xFF}, 200),
	}

	for i, seed := range seeds {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Seed %d panicked: %v", i, r)
				}
			}()
			_, _, _ = SplitIPv4TCPPacket(seed, 5)
		}()
	}
}

func TestSplitIPv4TCPPacket_IndependentChecksumVerification(t *testing.T) {
	cfg := DefaultPacketConfig()
	cfg.Payload = []byte("A quick brown fox jumps over the lazy dog. 1234567890!")
	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify input packet with independent oracle (both IPv4 header and TCP segment)
	if ok, reason := independentVerifyIPv4(pkt); !ok {
		t.Fatalf("Input packet failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(pkt); !ok {
		t.Fatalf("Input packet failed independent TCP oracle: %s", reason)
	}

	first, second, err := SplitIPv4TCPPacket(pkt, 20)
	if err != nil {
		t.Fatal(err)
	}

	// Verify Segment 1 with independent oracle (both IPv4 header and TCP segment)
	if ok, reason := independentVerifyIPv4(first); !ok {
		t.Fatalf("Segment 1 failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(first); !ok {
		t.Fatalf("Segment 1 failed independent TCP oracle: %s", reason)
	}

	// Verify Segment 2 with independent oracle (both IPv4 header and TCP segment)
	if ok, reason := independentVerifyIPv4(second); !ok {
		t.Fatalf("Segment 2 failed independent IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(second); !ok {
		t.Fatalf("Segment 2 failed independent TCP oracle: %s", reason)
	}
}

func TestSplitIPv4TCPPacket_MaxSizeAndOversized(t *testing.T) {
	t.Run("Valid maximum-size IPv4 packet (65535 bytes)", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		// IP header = 20, TCP header = 20. Max payload = 65535 - 40 = 65495 bytes.
		maxPayloadLen := MaxIPv4PacketLen - 40
		cfg.Payload = bytes.Repeat([]byte{0x5A}, maxPayloadLen)

		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket for max-size packet failed: %v", err)
		}
		if len(pkt) != MaxIPv4PacketLen {
			t.Fatalf("Constructed packet length = %d, expected %d", len(pkt), MaxIPv4PacketLen)
		}

		vIP, err := VerifyIPv4Checksum(pkt)
		if err != nil || !vIP {
			t.Fatalf("Max-size packet IPv4 checksum invalid: valid=%v, err=%v", vIP, err)
		}
		vTCP, err := VerifyTCPChecksum(pkt)
		if err != nil || !vTCP {
			t.Fatalf("Max-size packet TCP checksum invalid: valid=%v, err=%v", vTCP, err)
		}

		splitOffset := 30000
		first, second, err := SplitIPv4TCPPacket(pkt, splitOffset)
		if err != nil {
			t.Fatalf("SplitIPv4TCPPacket failed on max-size packet: %v", err)
		}

		p1, err := ParseIPv4TCPPacket(first)
		if err != nil {
			t.Fatalf("Parse segment 1 failed: %v", err)
		}
		p2, err := ParseIPv4TCPPacket(second)
		if err != nil {
			t.Fatalf("Parse segment 2 failed: %v", err)
		}

		if len(p1.Payload) != splitOffset {
			t.Fatalf("Segment 1 payload len = %d, want %d", len(p1.Payload), splitOffset)
		}
		expectedSeg2Len := maxPayloadLen - splitOffset
		if len(p2.Payload) != expectedSeg2Len {
			t.Fatalf("Segment 2 payload len = %d, want %d", len(p2.Payload), expectedSeg2Len)
		}

		if p1.SeqNum != cfg.SeqNum {
			t.Fatalf("Segment 1 seq = %d, want %d", p1.SeqNum, cfg.SeqNum)
		}
		expectedSeg2Seq := cfg.SeqNum + uint32(splitOffset)
		if p2.SeqNum != expectedSeg2Seq {
			t.Fatalf("Segment 2 seq = %d, want %d", p2.SeqNum, expectedSeg2Seq)
		}

		// Verify checksums of segments (production verifiers)
		v1IP, _ := VerifyIPv4Checksum(first)
		v1TCP, _ := VerifyTCPChecksum(first)
		v2IP, _ := VerifyIPv4Checksum(second)
		v2TCP, _ := VerifyTCPChecksum(second)
		if !v1IP || !v1TCP || !v2IP || !v2TCP {
			t.Fatalf("Segment checksum failure: seg1(IP=%v, TCP=%v), seg2(IP=%v, TCP=%v)", v1IP, v1TCP, v2IP, v2TCP)
		}

		// Independent oracle verification
		if ok, reason := independentVerifyIPv4(first); !ok {
			t.Fatalf("Max-size seg1 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(first); !ok {
			t.Fatalf("Max-size seg1 failed TCP oracle: %s", reason)
		}
		if ok, reason := independentVerifyIPv4(second); !ok {
			t.Fatalf("Max-size seg2 failed IPv4 oracle: %s", reason)
		}
		if ok, reason := independentVerifyTCP(second); !ok {
			t.Fatalf("Max-size seg2 failed TCP oracle: %s", reason)
		}

		// Byte reconstruction check
		reconstructed := append(append([]byte(nil), p1.Payload...), p2.Payload...)
		if !bytes.Equal(reconstructed, cfg.Payload) {
			t.Fatal("Max-size payload reconstruction mismatch")
		}
	})

	t.Run("Oversized packet rejected by ParseIPv4TCPPacket and SplitIPv4TCPPacket", func(t *testing.T) {
		oversized := make([]byte, MaxIPv4PacketLen+1) // 65536 bytes
		oversized[0] = 0x45
		_, err := ParseIPv4TCPPacket(oversized)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("Expected ErrPacketTooLarge from ParseIPv4TCPPacket, got: %v", err)
		}

		_, _, err = SplitIPv4TCPPacket(oversized, 100)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("Expected ErrPacketTooLarge from SplitIPv4TCPPacket, got: %v", err)
		}
	})

	t.Run("Oversized payload rejected by BuildIPv4TCPPacket", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = make([]byte, MaxIPv4PacketLen-39) // Total length would be 65536
		_, err := BuildIPv4TCPPacket(cfg)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("Expected ErrPacketTooLarge from BuildIPv4TCPPacket, got: %v", err)
		}
	})
}

func TestVerifyChecksums_InvalidInputs(t *testing.T) {
	t.Run("VerifyIPv4Checksum input checks", func(t *testing.T) {
		// Too short
		v, err := VerifyIPv4Checksum([]byte{0x45, 0x00})
		if v || !errors.Is(err, ErrPacketTooShort) {
			t.Fatalf("Expected ErrPacketTooShort, got (valid=%v, err=%v)", v, err)
		}

		// Non-IPv4 version
		v, err = VerifyIPv4Checksum(make([]byte, 20))
		if v || !errors.Is(err, ErrNotIPv4) {
			t.Fatalf("Expected ErrNotIPv4 for version 0, got (valid=%v, err=%v)", v, err)
		}

		// Invalid IHL (< 5)
		buf := make([]byte, 20)
		buf[0] = 0x44 // version 4, IHL 4
		v, err = VerifyIPv4Checksum(buf)
		if v || !errors.Is(err, ErrInvalidIHL) {
			t.Fatalf("Expected ErrInvalidIHL, got (valid=%v, err=%v)", v, err)
		}
	})

	t.Run("VerifyTCPChecksum input checks", func(t *testing.T) {
		// Too short
		v, err := VerifyTCPChecksum(make([]byte, 39))
		if v || !errors.Is(err, ErrPacketTooShort) {
			t.Fatalf("Expected ErrPacketTooShort, got (valid=%v, err=%v)", v, err)
		}

		// Non-IPv4 version
		v, err = VerifyTCPChecksum(make([]byte, 40))
		if v || !errors.Is(err, ErrNotIPv4) {
			t.Fatalf("Expected ErrNotIPv4, got (valid=%v, err=%v)", v, err)
		}

		// Non-TCP protocol (UDP)
		cfg := DefaultPacketConfig()
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pkt[9] = 17 // UDP
		v, err = VerifyTCPChecksum(pkt)
		if v || !errors.Is(err, ErrNotTCP) {
			t.Fatalf("Expected ErrNotTCP for protocol 17, got (valid=%v, err=%v)", v, err)
		}
	})
}

func TestChecksums_ZeroChecksumHandlingAndPreservedFields(t *testing.T) {
	cfg := DefaultPacketConfig()
	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatal(err)
	}

	p, err := ParseIPv4TCPPacket(pkt)
	if err != nil {
		t.Fatal(err)
	}

	// Calling IPv4Checksum on header with existing checksum should compute the same checksum
	// (because bytes 10..12 are treated as zero per RFC 791).
	hdr := pkt[:p.IHL]
	cs1 := IPv4Checksum(hdr)
	csOrig := binary.BigEndian.Uint16(hdr[10:12])
	if cs1 != csOrig {
		t.Fatalf("IPv4Checksum did not ignore existing checksum field: got 0x%04x, want 0x%04x", cs1, csOrig)
	}

	// Calling TCPChecksum on header with existing checksum should also compute the same checksum.
	tcpHdr := pkt[p.IHL : p.IHL+p.TCPDataOffset]
	csTCP, err := TCPChecksum(p.SrcIP, p.DstIP, tcpHdr, p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	csTCPOrig := binary.BigEndian.Uint16(tcpHdr[16:18])
	if csTCP != csTCPOrig {
		t.Fatalf("TCPChecksum did not ignore existing checksum field: got 0x%04x, want 0x%04x", csTCP, csTCPOrig)
	}
}

func TestSplitIPv4TCPPacket_IdentificationWraparound(t *testing.T) {
	cfg := DefaultPacketConfig()
	cfg.Identification = 0xFFFF // Max 16-bit identification
	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatal(err)
	}

	first, second, err := SplitIPv4TCPPacket(pkt, 10)
	if err != nil {
		t.Fatal(err)
	}

	p1, err := ParseIPv4TCPPacket(first)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Identification != 0xFFFF {
		t.Fatalf("Segment 1 identification = 0x%04x, want 0xFFFF", p1.Identification)
	}

	p2, err := ParseIPv4TCPPacket(second)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Identification != 0x0000 {
		t.Fatalf("Segment 2 identification wrapped mismatch: got 0x%04x, want 0x0000", p2.Identification)
	}

	// Independent oracle verification
	if ok, reason := independentVerifyIPv4(first); !ok {
		t.Fatalf("Segment 1 failed IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(first); !ok {
		t.Fatalf("Segment 1 failed TCP oracle: %s", reason)
	}
	if ok, reason := independentVerifyIPv4(second); !ok {
		t.Fatalf("Segment 2 failed IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(second); !ok {
		t.Fatalf("Segment 2 failed TCP oracle: %s", reason)
	}
}

func TestSplitIPv4TCPPacket_DontFragmentFlagPreservation(t *testing.T) {
	cfg := DefaultPacketConfig()
	cfg.DF = false // DF disabled
	pkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatal(err)
	}

	pOrig, err := ParseIPv4TCPPacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if pOrig.DF != false {
		t.Fatal("Original packet must have DF == false")
	}

	first, second, err := SplitIPv4TCPPacket(pkt, 12)
	if err != nil {
		t.Fatal(err)
	}

	p1, err := ParseIPv4TCPPacket(first)
	if err != nil {
		t.Fatal(err)
	}
	if p1.DF != false {
		t.Fatal("Segment 1 must preserve DF == false")
	}

	p2, err := ParseIPv4TCPPacket(second)
	if err != nil {
		t.Fatal(err)
	}
	if p2.DF != false {
		t.Fatal("Segment 2 must preserve DF == false")
	}

	// Checksums
	if ok, reason := independentVerifyIPv4(first); !ok {
		t.Fatalf("Segment 1 failed IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(first); !ok {
		t.Fatalf("Segment 1 failed TCP oracle: %s", reason)
	}
	if ok, reason := independentVerifyIPv4(second); !ok {
		t.Fatalf("Segment 2 failed IPv4 oracle: %s", reason)
	}
	if ok, reason := independentVerifyTCP(second); !ok {
		t.Fatalf("Segment 2 failed TCP oracle: %s", reason)
	}
}

func TestBuildDummyClientHello(t *testing.T) {
	// 1. Default SNI
	payloadDefault := BuildDummyClientHello("")
	if len(payloadDefault) < 5 {
		t.Fatalf("dummy payload too short: %d bytes", len(payloadDefault))
	}
	// Verify TLS record header: 0x16 0x03 0x01
	if payloadDefault[0] != 0x16 || payloadDefault[1] != 0x03 || payloadDefault[2] != 0x01 {
		t.Fatalf("invalid TLS record framing: %x %x %x", payloadDefault[0], payloadDefault[1], payloadDefault[2])
	}
	// Parse with tlsparse
	resDefault := tlsparse.ParseClientHello(payloadDefault, tlsparse.DefaultLimits())
	if resDefault.Status != tlsparse.StatusParsed {
		t.Fatalf("tlsparse failed to parse default dummy ClientHello: status=%s, reason=%s", resDefault.Status, resDefault.Reason)
	}
	if !resDefault.Metadata.HasSNI || resDefault.Metadata.SNI != DefaultDummySNI {
		t.Fatalf("expected SNI %q, got %q (hasSNI=%v)", DefaultDummySNI, resDefault.Metadata.SNI, resDefault.Metadata.HasSNI)
	}

	// 2. Custom SNI
	customSNI := "secure.proxy.internal"
	payloadCustom := BuildDummyClientHello(customSNI)
	resCustom := tlsparse.ParseClientHello(payloadCustom, tlsparse.DefaultLimits())
	if resCustom.Status != tlsparse.StatusParsed {
		t.Fatalf("tlsparse failed to parse custom dummy ClientHello: status=%s, reason=%s", resCustom.Status, resCustom.Reason)
	}
	if !resCustom.Metadata.HasSNI || resCustom.Metadata.SNI != customSNI {
		t.Fatalf("expected SNI %q, got %q (hasSNI=%v)", customSNI, resCustom.Metadata.SNI, resCustom.Metadata.HasSNI)
	}
	// 3. Whitespace-only SNI defaults to DefaultDummySNI
	payloadWhitespace := BuildDummyClientHello("   \t  ")
	resWhitespace := tlsparse.ParseClientHello(payloadWhitespace, tlsparse.DefaultLimits())
	if resWhitespace.Status != tlsparse.StatusParsed || resWhitespace.Metadata.SNI != DefaultDummySNI {
		t.Fatalf("whitespace SNI should default to %q, got status=%s, sni=%q", DefaultDummySNI, resWhitespace.Status, resWhitespace.Metadata.SNI)
	}

	// 4. Overly long SNI capped to 255 bytes
	longSNI := strings.Repeat("a", 300) + ".example.com"
	payloadLong := BuildDummyClientHello(longSNI)
	resLong := tlsparse.ParseClientHello(payloadLong, tlsparse.DefaultLimits())
	if resLong.Status != tlsparse.StatusParsed {
		t.Fatalf("tlsparse failed to parse capped long SNI: status=%s, reason=%s", resLong.Status, resLong.Reason)
	}
	if len(resLong.Metadata.SNI) > 255 {
		t.Fatalf("SNI length not capped: got %d bytes, want <= 255", len(resLong.Metadata.SNI))
	}
}

func TestSynthesizeFakeIPv4TCPPacket(t *testing.T) {
	cfg := DefaultPacketConfig()
	cfg.SrcPort = 11223
	cfg.DstPort = 443
	cfg.SeqNum = 55667788
	cfg.AckNum = 99887766
	cfg.Window = 43690
	cfg.Payload = []byte("Original TLS handshake payload goes here")

	origPkt, err := BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build original packet: %v", err)
	}
	origHash := sha256.Sum256(origPkt)

	dummyPayload := BuildDummyClientHello("poison.example.org")

	// 1. Validation: Empty dummy payload rejected
	_, err = SynthesizeFakeIPv4TCPPacket(origPkt, nil, 4, false)
	if !errors.Is(err, ErrEmptyDummyPayload) {
		t.Fatalf("expected ErrEmptyDummyPayload, got %v", err)
	}

	// 2. Validation: TTL boundaries (must be 2-16 if > 0)
	_, err = SynthesizeFakeIPv4TCPPacket(origPkt, dummyPayload, 1, false)
	if !errors.Is(err, ErrInvalidFakeTTL) {
		t.Fatalf("expected ErrInvalidFakeTTL for TTL=1, got %v", err)
	}
	_, err = SynthesizeFakeIPv4TCPPacket(origPkt, dummyPayload, 17, false)
	if !errors.Is(err, ErrInvalidFakeTTL) {
		t.Fatalf("expected ErrInvalidFakeTTL for TTL=17, got %v", err)
	}

	// 3. Low-TTL mode (TTL = 4, badChecksum = false)
	fakeTTL, err := SynthesizeFakeIPv4TCPPacket(origPkt, dummyPayload, 4, false)
	if err != nil {
		t.Fatalf("synthesize fake packet with TTL 4: %v", err)
	}
	parsedTTL, err := ParseIPv4TCPPacket(fakeTTL)
	if err != nil {
		t.Fatalf("parse fakeTTL packet: %v", err)
	}
	if parsedTTL.TTL != 4 {
		t.Fatalf("fake packet TTL = %d, want 4", parsedTTL.TTL)
	}
	if parsedTTL.SeqNum != cfg.SeqNum {
		t.Fatalf("fake packet SeqNum = %d, want %d", parsedTTL.SeqNum, cfg.SeqNum)
	}
	if parsedTTL.AckNum != cfg.AckNum {
		t.Fatalf("fake packet AckNum = %d, want %d", parsedTTL.AckNum, cfg.AckNum)
	}
	if parsedTTL.Window != cfg.Window {
		t.Fatalf("fake packet Window = %d, want %d", parsedTTL.Window, cfg.Window)
	}
	if parsedTTL.SrcPort != cfg.SrcPort || parsedTTL.DstPort != cfg.DstPort {
		t.Fatalf("fake packet port mismatch: src=%d, dst=%d", parsedTTL.SrcPort, parsedTTL.DstPort)
	}
	okIP, errIP := VerifyIPv4Checksum(fakeTTL)
	if !okIP || errIP != nil {
		t.Fatalf("fakeTTL IPv4 checksum invalid: ok=%v, err=%v", okIP, errIP)
	}
	okTCP, errTCP := VerifyTCPChecksum(fakeTTL)
	if !okTCP || errTCP != nil {
		t.Fatalf("fakeTTL TCP checksum invalid: ok=%v, err=%v", okTCP, errTCP)
	}

	// 4. Bad TCP Checksum mode (TTL = 0, badChecksum = true)
	fakeBadCS, err := SynthesizeFakeIPv4TCPPacket(origPkt, dummyPayload, 0, true)
	if err != nil {
		t.Fatalf("synthesize fake packet with bad checksum: %v", err)
	}
	parsedBadCS, err := ParseIPv4TCPPacket(fakeBadCS)
	if err != nil {
		t.Fatalf("parse fakeBadCS packet: %v", err)
	}
	if parsedBadCS.TTL != cfg.TTL {
		t.Fatalf("fakeBadCS TTL = %d, want original %d", parsedBadCS.TTL, cfg.TTL)
	}
	okIPBad, errIPBad := VerifyIPv4Checksum(fakeBadCS)
	if !okIPBad || errIPBad != nil {
		t.Fatalf("fakeBadCS IPv4 checksum invalid: ok=%v, err=%v", okIPBad, errIPBad)
	}
	okTCPBad, errTCPBad := VerifyTCPChecksum(fakeBadCS)
	if okTCPBad || errTCPBad != nil {
		t.Fatalf("fakeBadCS TCP checksum should be invalid, but got ok=%v, err=%v", okTCPBad, errTCPBad)
	}

	// 5. Combined mode (Low-TTL = 5 and badChecksum = true)
	fakeBoth, err := SynthesizeFakeIPv4TCPPacket(origPkt, dummyPayload, 5, true)
	if err != nil {
		t.Fatalf("synthesize fake packet with both: %v", err)
	}
	parsedBoth, err := ParseIPv4TCPPacket(fakeBoth)
	if err != nil {
		t.Fatalf("parse fakeBoth packet: %v", err)
	}
	if parsedBoth.TTL != 5 {
		t.Fatalf("fakeBoth TTL = %d, want 5", parsedBoth.TTL)
	}
	okIPBoth, errIPBoth := VerifyIPv4Checksum(fakeBoth)
	if !okIPBoth || errIPBoth != nil {
		t.Fatalf("fakeBoth IPv4 checksum invalid: ok=%v, err=%v", okIPBoth, errIPBoth)
	}
	okTCPBoth, errTCPBoth := VerifyTCPChecksum(fakeBoth)
	if okTCPBoth || errTCPBoth != nil {
		t.Fatalf("fakeBoth TCP checksum should be invalid, got ok=%v, err=%v", okTCPBoth, errTCPBoth)
	}

	// 6. Original packet immutability guarantee
	afterHash := sha256.Sum256(origPkt)
	if origHash != afterHash {
		t.Fatal("original packet was mutated by SynthesizeFakeIPv4TCPPacket")
	}

	// 7. Synthetic fake packet with IPv4 and TCP options preserved
	cfgWithOptions := DefaultPacketConfig()
	cfgWithOptions.IPv4Options = []byte{0x01, 0x01, 0x01, 0x00}                                                // 4 bytes NOPs
	cfgWithOptions.TCPOptions = []byte{0x01, 0x01, 0x08, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88} // 12 bytes TS
	cfgWithOptions.Payload = dummyPayload

	pktWithOptions, err := BuildIPv4TCPPacket(cfgWithOptions)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket with options: %v", err)
	}

	fakeWithOptions, err := SynthesizeFakeIPv4TCPPacket(pktWithOptions, dummyPayload, 3, true)
	if err != nil {
		t.Fatalf("SynthesizeFakeIPv4TCPPacket with options: %v", err)
	}
	parsedWithOptions, err := ParseIPv4TCPPacket(fakeWithOptions)
	if err != nil {
		t.Fatalf("ParseIPv4TCPPacket fakeWithOptions: %v", err)
	}
	if parsedWithOptions.TTL != 3 {
		t.Fatalf("TTL = %d, want 3", parsedWithOptions.TTL)
	}
	if !bytes.Equal(parsedWithOptions.IPv4Options, cfgWithOptions.IPv4Options) {
		t.Fatalf("IPv4 options not preserved in fake packet: got %x, want %x", parsedWithOptions.IPv4Options, cfgWithOptions.IPv4Options)
	}
	if !bytes.Equal(parsedWithOptions.TCPOptions, cfgWithOptions.TCPOptions) {
		t.Fatalf("TCP options not preserved in fake packet: got %x, want %x", parsedWithOptions.TCPOptions, cfgWithOptions.TCPOptions)
	}
	okIPOpt, errIPOpt := VerifyIPv4Checksum(fakeWithOptions)
	if !okIPOpt || errIPOpt != nil {
		t.Fatalf("fakeWithOptions IPv4 checksum invalid: ok=%v, err=%v", okIPOpt, errIPOpt)
	}
	okTCPOpt, errTCPOpt := VerifyTCPChecksum(fakeWithOptions)
	if okTCPOpt || errTCPOpt != nil {
		t.Fatalf("fakeWithOptions TCP checksum should be invalid (badChecksum=true), got ok=%v, err=%v", okTCPOpt, errTCPOpt)
	}
}

func TestBuildDummyHTTPRequest(t *testing.T) {
	// Default host
	reqDefault := BuildDummyHTTPRequest("")
	expectedDefault := "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
	if string(reqDefault) != expectedDefault {
		t.Fatalf("expected %q, got %q", expectedDefault, string(reqDefault))
	}

	// Custom host
	reqCustom := BuildDummyHTTPRequest("updates.discord.com")
	expectedCustom := "GET / HTTP/1.1\r\nHost: updates.discord.com\r\n\r\n"
	if string(reqCustom) != expectedCustom {
		t.Fatalf("expected %q, got %q", expectedCustom, string(reqCustom))
	}
}

func TestFindHTTPHost(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantHost  string
		wantFound bool
		wantVal   string
	}{
		{
			name:      "standard GET with Host",
			payload:   "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
			wantHost:  "example.com",
			wantFound: true,
			wantVal:   "example.com",
		},
		{
			name:      "lowercase host with spaces and port",
			payload:   "POST /api/v1 HTTP/1.1\r\nhost:   updates.discord.com:80  \r\nContent-Length: 0\r\n\r\n",
			wantHost:  "updates.discord.com:80",
			wantFound: true,
			wantVal:   "updates.discord.com:80",
		},
		{
			name:      "mixed case HoSt with tabs",
			payload:   "HEAD / HTTP/1.1\r\nHoSt:\troblox.com\t\r\n\r\n",
			wantHost:  "roblox.com",
			wantFound: true,
			wantVal:   "roblox.com",
		},
		{
			name:      "no host header",
			payload:   "GET / HTTP/1.1\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n",
			wantHost:  "",
			wantFound: false,
		},
		{
			name:      "empty payload",
			payload:   "",
			wantHost:  "",
			wantFound: false,
		},
		{
			name:      "truncated headers",
			payload:   "GET",
			wantHost:  "",
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, start, end, found := FindHTTPHost([]byte(tc.payload))
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if found {
				if host != tc.wantHost {
					t.Fatalf("host = %q, want %q", host, tc.wantHost)
				}
				val := tc.payload[start:end]
				if val != tc.wantVal {
					t.Fatalf("sliced val = %q, want %q", val, tc.wantVal)
				}
			}
		})
	}
}

func TestSubsegmentIPv4TCPPacket(t *testing.T) {
	t.Run("payload under MTU returns single packet", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.Payload = bytes.Repeat([]byte{0x55}, 800)
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}

		segs, err := SubsegmentIPv4TCPPacket(pkt, MaxSegmentPayload)
		if err != nil {
			t.Fatalf("subsegment failed: %v", err)
		}
		if len(segs) != 1 {
			t.Fatalf("expected 1 segment, got %d", len(segs))
		}
		if !bytes.Equal(segs[0], pkt) {
			t.Fatal("segment should match original packet when <= maxPayload")
		}
	})

	t.Run("post-quantum 1910-byte payload split into <=1400 byte chunks", func(t *testing.T) {
		const totalPayloadLen = 1910
		origPayload := make([]byte, totalPayloadLen)
		for i := range origPayload {
			origPayload[i] = byte(i % 251)
		}

		cfg := DefaultPacketConfig()
		cfg.SeqNum = 50000
		cfg.TCPFlags = TCPFlagACK | TCPFlagPSH
		cfg.Payload = origPayload

		origPkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}

		segs, err := SubsegmentIPv4TCPPacket(origPkt, MaxSegmentPayload)
		if err != nil {
			t.Fatalf("subsegment failed: %v", err)
		}

		if len(segs) != 2 {
			t.Fatalf("expected 2 segments for 1910-byte payload, got %d", len(segs))
		}

		var reassembledPayload []byte
		for i, seg := range segs {
			if len(seg) > 1460 {
				t.Errorf("segment %d wire length %d exceeds 1460 bytes", i, len(seg))
			}

			parsed, err := ParseIPv4TCPPacket(seg)
			if err != nil {
				t.Fatalf("parse segment %d: %v", i, err)
			}

			if len(parsed.Payload) > MaxSegmentPayload {
				t.Errorf("segment %d payload length %d exceeds MaxSegmentPayload (%d)", i, len(parsed.Payload), MaxSegmentPayload)
			}

			// Validate checksums with independent oracles
			if ok, reason := independentVerifyIPv4(seg); !ok {
				t.Errorf("segment %d invalid IPv4 checksum: %s", i, reason)
			}
			if ok, reason := independentVerifyTCP(seg); !ok {
				t.Errorf("segment %d invalid TCP checksum: %s", i, reason)
			}

			// Verify sequence numbers
			expectedSeq := cfg.SeqNum + uint32(i*MaxSegmentPayload)
			if parsed.SeqNum != expectedSeq {
				t.Errorf("segment %d SeqNum: got %d, want %d", i, parsed.SeqNum, expectedSeq)
			}

			// Verify PSH flag
			if i < len(segs)-1 {
				if (parsed.TCPFlags & TCPFlagPSH) != 0 {
					t.Errorf("intermediate segment %d has PSH flag set", i)
				}
			} else {
				if (parsed.TCPFlags & TCPFlagPSH) == 0 {
					t.Errorf("final segment %d missing PSH flag", i)
				}
			}

			reassembledPayload = append(reassembledPayload, parsed.Payload...)
		}

		if !bytes.Equal(reassembledPayload, origPayload) {
			t.Fatal("reassembled subsegment payload does not match original payload")
		}
	})

	t.Run("boundary checks", func(t *testing.T) {
		// Exactly 1400 bytes -> 1 segment
		cfg := DefaultPacketConfig()
		cfg.Payload = bytes.Repeat([]byte{0xAA}, 1400)
		pkt, _ := BuildIPv4TCPPacket(cfg)
		segs, err := SubsegmentIPv4TCPPacket(pkt, 1400)
		if err != nil || len(segs) != 1 {
			t.Fatalf("1400 bytes: expected 1 segment, got %d, err %v", len(segs), err)
		}

		// Exactly 1401 bytes -> 2 segments (1400 + 1)
		cfg.Payload = bytes.Repeat([]byte{0xBB}, 1401)
		pkt, _ = BuildIPv4TCPPacket(cfg)
		segs, err = SubsegmentIPv4TCPPacket(pkt, 1400)
		if err != nil || len(segs) != 2 {
			t.Fatalf("1401 bytes: expected 2 segments, got %d, err %v", len(segs), err)
		}

		// 4000 bytes -> 3 segments (1400 + 1400 + 1200)
		cfg.Payload = bytes.Repeat([]byte{0xCC}, 4000)
		pkt, _ = BuildIPv4TCPPacket(cfg)
		segs, err = SubsegmentIPv4TCPPacket(pkt, 1400)
		if err != nil || len(segs) != 3 {
			t.Fatalf("4000 bytes: expected 3 segments, got %d, err %v", len(segs), err)
		}
	})

	t.Run("packet with IP and TCP options never exceeds 1500 wire MTU", func(t *testing.T) {
		cfg := DefaultPacketConfig()
		cfg.IPv4Options = bytes.Repeat([]byte{0x01}, 20) // 20 bytes NOP options (IHL = 40)
		cfg.TCPOptions = bytes.Repeat([]byte{0x01}, 20)  // 20 bytes NOP options (TCPDataOffset = 40)
		cfg.Payload = bytes.Repeat([]byte{0xDD}, 2000)   // 2000 bytes payload
		pkt, err := BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("build packet with options: %v", err)
		}
		if len(pkt) != 40+40+2000 {
			t.Fatalf("expected packet length %d, got %d", 40+40+2000, len(pkt))
		}

		segs, err := SubsegmentIPv4TCPPacket(pkt, MaxSegmentPayload)
		if err != nil {
			t.Fatalf("subsegment with options failed: %v", err)
		}

		for i, seg := range segs {
			if len(seg) > 1500 {
				t.Errorf("segment %d wire length %d exceeds 1500 bytes MTU limit", i, len(seg))
			}
			if ok, reason := independentVerifyIPv4(seg); !ok {
				t.Errorf("segment %d invalid IPv4 checksum: %s", i, reason)
			}
			if ok, reason := independentVerifyTCP(seg); !ok {
				t.Errorf("segment %d invalid TCP checksum: %s", i, reason)
			}
		}
	})
}

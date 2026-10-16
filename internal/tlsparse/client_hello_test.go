package tlsparse

import (
	"bytes"
	"testing"
)

func TestParsePartialClientHelloSNI_PostQuantumDiscord(t *testing.T) {
	// 1. Build a 1,950-byte Post-Quantum TLS 1.3 ClientHello (X25519MLKEM768)
	// containing SNI "gateway.discord.gg".
	const sni = "gateway.discord.gg"
	// Key share / MLKEM768 dummy payload (1850 bytes)
	extraExts := map[uint16][]byte{
		0x0033: bytes.Repeat([]byte{0xAA}, 1850), // key_share extension
	}
	rawHandshake := buildSyntheticClientHello(sni, extraExts)
	fullWire := wrapInSingleRecord(rawHandshake)

	if len(fullWire) < 1900 {
		t.Fatalf("expected fullWire >= 1900 bytes, got %d", len(fullWire))
	}

	// 2. Pre-segment into Packet 1 (1460 bytes) and Packet 2 (remaining bytes)
	packet1 := fullWire[:1460]
	packet2 := fullWire[1460:]

	// 3. Confirm standard ParseClientHello rejects Packet 1 as incomplete/need more data
	stdRes := ParseClientHello(packet1, DefaultLimits())
	if stdRes.Status != StatusNeedMoreData {
		t.Fatalf("expected ParseClientHello on Packet 1 to return StatusNeedMoreData, got %v", stdRes.Status)
	}

	// 4. Verify ParsePartialClientHelloSNI successfully extracts SNI from Packet 1
	meta, err := ParsePartialClientHelloSNI(packet1)
	if err != nil {
		t.Fatalf("ParsePartialClientHelloSNI failed on Packet 1: %v", err)
	}
	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if !meta.HasSNI {
		t.Fatal("expected HasSNI = true")
	}
	if meta.SNI != sni {
		t.Fatalf("expected SNI %q, got %q", sni, meta.SNI)
	}

	// 5. Verify logical offsets accurately index the SNI hostname
	handshakeInPacket1 := packet1[5:]
	extracted := string(handshakeInPacket1[meta.LogicalSNIOffsetStart:meta.LogicalSNIOffsetEnd])
	if extracted != sni {
		t.Fatalf("logical offset slice mismatch: got %q, want %q", extracted, sni)
	}

	// Verify synthetic records in meta
	if len(meta.Records) != 1 {
		t.Fatalf("expected 1 record boundary, got %d", len(meta.Records))
	}
	if meta.Records[0].PayloadConsumed != len(packet1)-5 {
		t.Fatalf("expected PayloadConsumed=%d, got %d", len(packet1)-5, meta.Records[0].PayloadConsumed)
	}

	// 6. Packet 2 should NOT start with TLS handshake record header
	if len(packet2) > 0 && packet2[0] == 0x16 {
		t.Errorf("Packet 2 should not start with TLS handshake record header 0x16")
	}
}

func TestParsePartialClientHelloSNI_EdgeCases(t *testing.T) {
	t.Run("too short for header", func(t *testing.T) {
		_, err := ParsePartialClientHelloSNI([]byte{0x16, 0x03, 0x01})
		if err == nil {
			t.Fatal("expected error for short buffer")
		}
	})

	t.Run("not handshake", func(t *testing.T) {
		_, err := ParsePartialClientHelloSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x00})
		if err == nil {
			t.Fatal("expected error for application data record")
		}
	})

	t.Run("not ClientHello", func(t *testing.T) {
		// HandshakeType 0x02 (ServerHello)
		rec := []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c, 0x03, 0x03}
		_, err := ParsePartialClientHelloSNI(rec)
		if err == nil {
			t.Fatal("expected error for non-ClientHello")
		}
	})

	t.Run("valid ClientHello without SNI", func(t *testing.T) {
		raw := buildSyntheticClientHello("", nil)
		wire := wrapInSingleRecord(raw)
		_, err := ParsePartialClientHelloSNI(wire)
		if err == nil {
			t.Fatal("expected error when SNI is missing")
		}
	})

	t.Run("various target hostnames", func(t *testing.T) {
		targets := []string{"discord.com", "updates.discord.com", "gateway.discord.gg", "www.roblox.com"}
		for _, target := range targets {
			raw := buildSyntheticClientHello(target, nil)
			wire := wrapInSingleRecord(raw)
			meta, err := ParsePartialClientHelloSNI(wire)
			if err != nil {
				t.Fatalf("target %s failed: %v", target, err)
			}
			if meta.SNI != target {
				t.Errorf("target %s: got SNI %s", target, meta.SNI)
			}
		}
	})
}

func TestFindContinuationSNI(t *testing.T) {
	t.Run("RFC 6066 SNI in continuation payload", func(t *testing.T) {
		sni := "gateway.discord.gg"
		// Build RFC 6066 server_name extension bytes:
		// 0x00 0x00 (extType), extLen (2B), listLen (2B), 0x00 (nameType), hostLen (2B), hostname
		hostBytes := []byte(sni)
		listLen := 1 + 2 + len(hostBytes)
		extLen := 2 + listLen
		buf := new(bytes.Buffer)
		// Prefix some dummy continuation bytes (e.g. end of previous extension)
		buf.Write([]byte{0xde, 0xad, 0xbe, 0xef})
		// Server name extension
		buf.Write([]byte{0x00, 0x00})
		buf.WriteByte(byte(extLen >> 8))
		buf.WriteByte(byte(extLen & 0xff))
		buf.WriteByte(byte(listLen >> 8))
		buf.WriteByte(byte(listLen & 0xff))
		buf.WriteByte(0x00) // nameType = host_name
		buf.WriteByte(byte(len(hostBytes) >> 8))
		buf.WriteByte(byte(len(hostBytes) & 0xff))
		buf.Write(hostBytes)
		// Suffix some padding
		buf.Write(bytes.Repeat([]byte{0x00}, 20))

		cont, err := FindContinuationSNI(buf.Bytes())
		if err != nil {
			t.Fatalf("FindContinuationSNI failed: %v", err)
		}
		if cont.SNI != sni {
			t.Errorf("got SNI %q, want %q", cont.SNI, sni)
		}
		if cont.SNIStart != 4+9 {
			t.Errorf("got SNIStart %d, want %d", cont.SNIStart, 4+9)
		}
		if cont.SNIEnd != cont.SNIStart+len(sni) {
			t.Errorf("got SNIEnd %d, want %d", cont.SNIEnd, cont.SNIStart+len(sni))
		}
		if cont.SplitOffset <= cont.SNIStart || cont.SplitOffset >= cont.SNIEnd {
			t.Errorf("SplitOffset %d not inside SNI [%d, %d]", cont.SplitOffset, cont.SNIStart, cont.SNIEnd)
		}
	})

	t.Run("Secondary nameType scan", func(t *testing.T) {
		sni := "discord.com"
		hostBytes := []byte(sni)
		buf := new(bytes.Buffer)
		buf.Write([]byte{0x12, 0x34})
		buf.WriteByte(0x00) // nameType
		buf.WriteByte(byte(len(hostBytes) >> 8))
		buf.WriteByte(byte(len(hostBytes) & 0xff))
		buf.Write(hostBytes)

		cont, err := FindContinuationSNI(buf.Bytes())
		if err != nil {
			t.Fatalf("FindContinuationSNI failed: %v", err)
		}
		if cont.SNI != sni {
			t.Errorf("got SNI %q, want %q", cont.SNI, sni)
		}
	})

	t.Run("Fallback domain scan", func(t *testing.T) {
		payload := []byte("...some binary data...\x00\x05gateway.discord.gg\x00padding...")
		cont, err := FindContinuationSNI(payload)
		if err != nil {
			t.Fatalf("FindContinuationSNI fallback failed: %v", err)
		}
		if cont.SNI != "gateway.discord.gg" {
			t.Errorf("got SNI %q, want %q", cont.SNI, "gateway.discord.gg")
		}
	})

	t.Run("No SNI in payload", func(t *testing.T) {
		payload := bytes.Repeat([]byte{0x00, 0x01, 0x02}, 10)
		_, err := FindContinuationSNI(payload)
		if err == nil {
			t.Fatal("expected error when no SNI in payload, got nil")
		}
	})
}

package tlsparse

import (
	"bytes"
	"encoding/binary"
)

// buildSyntheticClientHello creates a complete, valid ClientHello message and wraps it in TLS record(s).
func buildSyntheticClientHello(sni string, extraExts map[uint16][]byte) []byte {
	handshakeBody := bytes.Buffer{}

	// Legacy Version: TLS 1.2 (0x0303)
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x0303))

	// Client Random: 32 bytes
	handshakeBody.Write(bytes.Repeat([]byte{0x42}, 32))

	// Session ID: 0 length
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

	// SNI Extension
	if sni != "" {
		sniData := bytes.Buffer{}
		// ServerNameList length
		listLen := uint16(1 + 2 + len(sni))
		_ = binary.Write(&sniData, binary.BigEndian, listLen)
		// NameType: host_name (0x00)
		sniData.WriteByte(0x00)
		// HostName length
		_ = binary.Write(&sniData, binary.BigEndian, uint16(len(sni)))
		// HostName
		sniData.WriteString(sni)

		// Extension Type 0x0000 + length
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x0000))
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(sniData.Len()))
		extensionsBuf.Write(sniData.Bytes())
	}

	// Extra Extensions (e.g. supported_versions, padding, etc.)
	for extType, data := range extraExts {
		_ = binary.Write(&extensionsBuf, binary.BigEndian, extType)
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(len(data)))
		extensionsBuf.Write(data)
	}

	if extensionsBuf.Len() > 0 {
		_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(extensionsBuf.Len()))
		handshakeBody.Write(extensionsBuf.Bytes())
	}

	// Full Handshake message: Type 0x01 + uint24 length + body
	fullHandshake := bytes.Buffer{}
	fullHandshake.WriteByte(0x01) // HandshakeType ClientHello
	bodyLen := handshakeBody.Len()
	fullHandshake.WriteByte(byte(bodyLen >> 16))
	fullHandshake.WriteByte(byte(bodyLen >> 8))
	fullHandshake.WriteByte(byte(bodyLen & 0xFF))
	fullHandshake.Write(handshakeBody.Bytes())

	return fullHandshake.Bytes()
}

// wrapInSingleRecord frames payload in a standard 5-byte TLS record header (0x16, 0x0301).
func wrapInSingleRecord(payload []byte) []byte {
	rec := bytes.Buffer{}
	rec.WriteByte(0x16)                                            // ContentType: Handshake
	_ = binary.Write(&rec, binary.BigEndian, uint16(0x0301))       // Version: TLS 1.0 legacy
	_ = binary.Write(&rec, binary.BigEndian, uint16(len(payload))) // Payload length
	rec.Write(payload)
	return rec.Bytes()
}

// wrapInFragmentedRecords splits payload at splitOffset across 2 TLS records.
func wrapInFragmentedRecords(payload []byte, splitOffset int) []byte {
	rec1Payload := payload[:splitOffset]
	rec2Payload := payload[splitOffset:]

	out := bytes.Buffer{}
	out.Write(wrapInSingleRecord(rec1Payload))
	out.Write(wrapInSingleRecord(rec2Payload))
	return out.Bytes()
}

// reconstructLogicalHandshake extracts and concatenates the consumed payload bytes from each record.
func reconstructLogicalHandshake(wire []byte, records []RecordBoundary) []byte {
	var logical []byte
	for _, r := range records {
		start := r.WireOffset + r.HeaderLen
		end := start + r.PayloadConsumed
		logical = append(logical, wire[start:end]...)
	}
	return logical
}

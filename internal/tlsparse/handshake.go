package tlsparse

import (
	"encoding/binary"
)

const (
	extensionTypeServerName uint16 = 0x0000
	serverNameTypeHostName  byte   = 0x00
)

// parseClientHelloBody parses the de-fragmented logical handshake message and extracts metadata.
// The logicalHandshake buffer begins with HandshakeType (0x01) at byte 0.
func parseClientHelloBody(logicalHandshake []byte, meta *ClientHelloMetadata) ParseResult {
	// Handshake header is 4 bytes: HandshakeType (1 byte) + uint24 length (3 bytes)
	// ClientHello body must contain at least: Version (2) + Random (32) + SessionID len (1) = 35 bytes
	if len(logicalHandshake) < 4+35 {
		return ParseResult{
			Status: StatusMalformed,
			Reason: "client_hello_body_truncated",
		}
	}

	meta.LegacyVersion = binary.BigEndian.Uint16(logicalHandshake[4:6])

	// Cursor i points into logicalHandshake
	i := 4 + 2 + 32 // skip 4 header + 2 version + 32 random bytes

	// Session ID
	if i >= len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "session_id_length_missing"}
	}
	sessIDLen := int(logicalHandshake[i])
	i++
	if i+sessIDLen > len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "session_id_out_of_bounds"}
	}
	i += sessIDLen

	// Cipher Suites
	if i+2 > len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "cipher_suites_length_missing"}
	}
	csLen := int(binary.BigEndian.Uint16(logicalHandshake[i : i+2]))
	i += 2
	if csLen < 2 || csLen%2 != 0 || i+csLen > len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "cipher_suites_out_of_bounds"}
	}
	numSuites := csLen / 2
	meta.CipherSuites = make([]uint16, numSuites)
	for s := 0; s < numSuites; s++ {
		meta.CipherSuites[s] = binary.BigEndian.Uint16(logicalHandshake[i+2*s : i+2*s+2])
	}
	i += csLen

	// Compression Methods
	if i >= len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "compression_methods_length_missing"}
	}
	compLen := int(logicalHandshake[i])
	i++
	if compLen < 1 || i+compLen > len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "compression_methods_out_of_bounds"}
	}
	meta.CompressionMethods = make([]byte, compLen)
	copy(meta.CompressionMethods, logicalHandshake[i:i+compLen])
	i += compLen

	// Extensions (optional if message ends here)
	if i == len(logicalHandshake) {
		meta.HasSNI = false
		return ParseResult{Status: StatusParsed, Metadata: meta}
	}

	if i+2 > len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "extensions_length_truncated"}
	}
	extsLen := int(binary.BigEndian.Uint16(logicalHandshake[i : i+2]))
	i += 2
	if i+extsLen != len(logicalHandshake) {
		return ParseResult{Status: StatusMalformed, Reason: "extensions_vector_length_mismatch"}
	}

	seenExtensions := make(map[uint16]bool)
	extsEnd := i + extsLen

	for i < extsEnd {
		if i+4 > extsEnd {
			return ParseResult{Status: StatusMalformed, Reason: "extension_header_truncated"}
		}
		extType := binary.BigEndian.Uint16(logicalHandshake[i : i+2])
		extLen := int(binary.BigEndian.Uint16(logicalHandshake[i+2 : i+4]))
		i += 4

		if i+extLen > extsEnd {
			return ParseResult{Status: StatusMalformed, Reason: "extension_length_out_of_bounds"}
		}

		// RFC 8446 Section 4.2: Extensions of the same type MUST NOT appear more than once
		if seenExtensions[extType] {
			return ParseResult{Status: StatusMalformed, Reason: "duplicate_extension"}
		}
		seenExtensions[extType] = true

		if extType == extensionTypeServerName {
			// Parse SNI extension payload (RFC 6066 Section 3)
			sniPayload := logicalHandshake[i : i+extLen]
			if len(sniPayload) < 2 {
				return ParseResult{Status: StatusMalformed, Reason: "sni_list_length_truncated"}
			}
			listLen := int(binary.BigEndian.Uint16(sniPayload[0:2]))
			if listLen+2 != len(sniPayload) || listLen < 3 {
				return ParseResult{Status: StatusMalformed, Reason: "sni_list_length_mismatch"}
			}

			nameType := sniPayload[2]
			if nameType == serverNameTypeHostName {
				hostNameLen := int(binary.BigEndian.Uint16(sniPayload[3:5]))
				if 5+hostNameLen > len(sniPayload) || hostNameLen == 0 {
					return ParseResult{Status: StatusMalformed, Reason: "sni_hostname_out_of_bounds"}
				}

				// Calculate exact logical offsets in the full logicalHandshake slice
				// i is the start of this extension's payload
				sniStart := i + 5
				sniEnd := sniStart + hostNameLen

				meta.HasSNI = true
				meta.SNI = string(logicalHandshake[sniStart:sniEnd])
				meta.LogicalSNIOffsetStart = sniStart
				meta.LogicalSNIOffsetEnd = sniEnd
			}
		}

		i += extLen
	}

	return ParseResult{
		Status:   StatusParsed,
		Metadata: meta,
	}
}

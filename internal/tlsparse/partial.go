package tlsparse

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrNotTLSHandshake         = errors.New("not a TLS handshake record")
	ErrUnsupportedVersion      = errors.New("unsupported TLS record version")
	ErrPayloadTooShort         = errors.New("payload too short for TLS ClientHello")
	ErrNotClientHello          = errors.New("handshake message is not ClientHello")
	ErrPartialSNINotFound      = errors.New("server_name extension not found in partial payload")
	ErrMalformedHandshake      = errors.New("malformed handshake framing in partial payload")
	ErrContinuationSNINotFound = errors.New("server_name extension or hostname not found in continuation payload")
)

// ParsePartialClientHelloSNI analyzes a potentially pre-segmented TLS ClientHello packet
// (such as a ~1,900-byte Post-Quantum TLS 1.3 ClientHello segmented into a 1,460-byte Packet 1).
// Even if the declared TLS record or handshake length extends past the end of the packet,
// this function walks available handshake fields and extensions to extract the SNI hostname,
// logical SNI offsets, and synthetic record metadata required for out-of-order desync splitting.
func ParsePartialClientHelloSNI(payload []byte) (*ClientHelloMetadata, error) {
	if len(payload) < recordHeaderLen {
		return nil, ErrPayloadTooShort
	}

	if payload[0] != contentTypeHandshake {
		return nil, ErrNotTLSHandshake
	}

	recVer := binary.BigEndian.Uint16(payload[1:3])
	if !isAcceptableRecordVersion(recVer) {
		return nil, fmt.Errorf("%w: 0x%04x", ErrUnsupportedVersion, recVer)
	}

	declaredRecLen := int(binary.BigEndian.Uint16(payload[3:5]))

	if len(payload) < recordHeaderLen+4 {
		return nil, ErrPayloadTooShort
	}

	handshake := payload[recordHeaderLen:]
	if handshake[0] != handshakeTypeClientHello {
		return nil, fmt.Errorf("%w: 0x%02x", ErrNotClientHello, handshake[0])
	}

	declaredBodyLen := int(uint32(handshake[1])<<16 | uint32(handshake[2])<<8 | uint32(handshake[3]))
	logicalHandshakeLen := 4 + declaredBodyLen

	// Minimum fixed ClientHello fields:
	// 4 (handshake hdr) + 2 (legacy version) + 32 (random) + 1 (session ID len) = 39 bytes
	if len(handshake) < 39 {
		return nil, ErrPayloadTooShort
	}

	legacyVer := binary.BigEndian.Uint16(handshake[4:6])

	// Session ID
	i := 38
	sessIDLen := int(handshake[i])
	i++
	if i+sessIDLen > len(handshake) {
		return nil, ErrPayloadTooShort
	}
	i += sessIDLen

	// Cipher Suites
	if i+2 > len(handshake) {
		return nil, ErrPayloadTooShort
	}
	csLen := int(binary.BigEndian.Uint16(handshake[i : i+2]))
	i += 2
	if csLen < 2 || csLen%2 != 0 || i+csLen > len(handshake) {
		return nil, ErrMalformedHandshake
	}
	numSuites := csLen / 2
	cipherSuites := make([]uint16, numSuites)
	for s := 0; s < numSuites; s++ {
		cipherSuites[s] = binary.BigEndian.Uint16(handshake[i+2*s : i+2*s+2])
	}
	i += csLen

	// Compression Methods
	if i >= len(handshake) {
		return nil, ErrPayloadTooShort
	}
	compLen := int(handshake[i])
	i++
	if compLen < 1 || i+compLen > len(handshake) {
		return nil, ErrMalformedHandshake
	}
	compMethods := make([]byte, compLen)
	copy(compMethods, handshake[i:i+compLen])
	i += compLen

	// Extensions
	if i == len(handshake) {
		return nil, ErrPartialSNINotFound
	}
	if i+2 > len(handshake) {
		return nil, ErrPayloadTooShort
	}
	extsLen := int(binary.BigEndian.Uint16(handshake[i : i+2]))
	i += 2

	extsEnd := len(handshake)
	if i+extsLen < extsEnd {
		extsEnd = i + extsLen
	}

	seenExtensions := make(map[uint16]bool)
	for i+4 <= extsEnd {
		extType := binary.BigEndian.Uint16(handshake[i : i+2])
		extLen := int(binary.BigEndian.Uint16(handshake[i+2 : i+4]))
		i += 4

		if i+extLen > extsEnd {
			// Extension truncated across packet boundary
			break
		}

		if seenExtensions[extType] {
			return nil, errors.New("duplicate extension in partial handshake")
		}
		seenExtensions[extType] = true

		if extType == extensionTypeServerName {
			sniPayload := handshake[i : i+extLen]
			if len(sniPayload) < 2 {
				return nil, ErrMalformedHandshake
			}
			listLen := int(binary.BigEndian.Uint16(sniPayload[0:2]))
			if listLen+2 != len(sniPayload) || listLen < 3 {
				return nil, ErrMalformedHandshake
			}
			nameType := sniPayload[2]
			if nameType == serverNameTypeHostName {
				hostNameLen := int(binary.BigEndian.Uint16(sniPayload[3:5]))
				if 5+hostNameLen > len(sniPayload) || hostNameLen == 0 {
					return nil, ErrMalformedHandshake
				}
				sniStart := i + 5
				sniEnd := sniStart + hostNameLen

				meta := &ClientHelloMetadata{
					HasSNI:             true,
					SNI:                string(handshake[sniStart:sniEnd]),
					LegacyVersion:      legacyVer,
					CipherSuites:       cipherSuites,
					CompressionMethods: compMethods,
					LogicalHandshakeLength: func() int {
						if logicalHandshakeLen > 0 {
							return logicalHandshakeLen
						}
						return len(handshake)
					}(),
					LogicalSNIOffsetStart: sniStart,
					LogicalSNIOffsetEnd:   sniEnd,
					Records: []RecordBoundary{
						{
							WireOffset:       0,
							HeaderLen:        recordHeaderLen,
							PayloadLen:       declaredRecLen,
							PayloadConsumed:  len(payload) - recordHeaderLen,
							PayloadRemaining: 0,
							Version:          recVer,
							ContentType:      contentTypeHandshake,
						},
					},
					ConsumedWireBytes: len(payload),
					IsFragmented:      true,
					HasTrailingData:   false,
				}
				return meta, nil
			}
		}

		i += extLen
	}

	return nil, ErrPartialSNINotFound
}

// ContinuationSNI holds the extracted SNI hostname and its physical offsets
// within a multi-packet TLS ClientHello continuation payload (Packet 2).
type ContinuationSNI struct {
	SNI         string
	SNIStart    int // Offset of hostname start in payload
	SNIEnd      int // Offset of hostname end in payload
	SplitOffset int // Mid-SNI split offset relative to payload start
}

// FindContinuationSNI scans the payload of a continuation TCP segment (Packet 2)
// for the TLS server_name (SNI) extension or embedded hostname bytes.
// It returns the extracted SNI, the byte boundaries, and the recommended sni-mid split offset.
func FindContinuationSNI(payload []byte) (*ContinuationSNI, error) {
	if len(payload) < 4 {
		return nil, ErrPayloadTooShort
	}

	// 1. Primary Scan: RFC 6066 server_name extension:
	// Type 0x0000 (2B), extLen (2B), listLen (2B), nameType 0x00 (1B), hostLen (2B), hostName bytes
	for i := 0; i+9 <= len(payload); i++ {
		if payload[i] == 0x00 && payload[i+1] == 0x00 {
			extLen := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))
			listLen := int(binary.BigEndian.Uint16(payload[i+4 : i+6]))
			nameType := payload[i+6]
			hostLen := int(binary.BigEndian.Uint16(payload[i+7 : i+9]))

			if nameType == 0 && hostLen > 0 &&
				extLen == listLen+2 &&
				listLen == hostLen+3 &&
				i+9+hostLen <= len(payload) {
				hostBytes := payload[i+9 : i+9+hostLen]
				if isValidHostname(hostBytes) {
					sni := string(hostBytes)
					start := i + 9
					end := start + hostLen
					mid := (start + end) / 2
					if mid <= 0 || mid >= len(payload) {
						mid = len(payload) / 2
					}
					return &ContinuationSNI{
						SNI:         sni,
						SNIStart:    start,
						SNIEnd:      end,
						SplitOffset: mid,
					}, nil
				}
			}
		}
	}

	// 2. Secondary Scan: nameType 0x00 + hostLen (2B) + valid hostname
	// (e.g. extension type/length was split at the boundary of Packet 1 and Packet 2)
	for i := 0; i+3 <= len(payload); i++ {
		if payload[i] == 0x00 {
			hostLen := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
			if hostLen >= 4 && i+3+hostLen <= len(payload) {
				hostBytes := payload[i+3 : i+3+hostLen]
				if isValidHostname(hostBytes) {
					sni := string(hostBytes)
					start := i + 3
					end := start + hostLen
					mid := (start + end) / 2
					if mid <= 0 || mid >= len(payload) {
						mid = len(payload) / 2
					}
					return &ContinuationSNI{
						SNI:         sni,
						SNIStart:    start,
						SNIEnd:      end,
						SplitOffset: mid,
					}, nil
				}
			}
		}
	}

	// 3. Fallback Scan: scan for valid domain name string sequences with at least one dot
	// (e.g. "gateway.discord.gg", "discord.com")
	for i := 0; i < len(payload); i++ {
		if isHostChar(payload[i]) {
			j := i
			for j < len(payload) && isHostChar(payload[j]) {
				j++
			}
			hostBytes := payload[i:j]
			if isValidHostname(hostBytes) && len(hostBytes) >= 4 {
				sni := string(hostBytes)
				start := i
				end := j
				mid := (start + end) / 2
				if mid <= 0 || mid >= len(payload) {
					mid = len(payload) / 2
				}
				return &ContinuationSNI{
					SNI:         sni,
					SNIStart:    start,
					SNIEnd:      end,
					SplitOffset: mid,
				}, nil
			}
			i = j
		}
	}

	return nil, ErrContinuationSNINotFound
}

func isHostChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
}

func isValidHostname(b []byte) bool {
	if len(b) < 3 || len(b) > 253 {
		return false
	}
	hasDot := false
	for _, c := range b {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c == '.' {
			hasDot = true
			continue
		}
		return false
	}
	return hasDot && b[0] != '.' && b[0] != '-' && b[len(b)-1] != '.' && b[len(b)-1] != '-'
}

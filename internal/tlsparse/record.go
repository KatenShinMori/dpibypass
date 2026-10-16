package tlsparse

import (
	"encoding/binary"
	"fmt"
)

const (
	recordHeaderLen = 5

	// TLS Content Types (RFC 5246 Section 6.2.1, RFC 8446 Section 5.1)
	contentTypeChangeCipherSpec byte = 0x14
	contentTypeAlert            byte = 0x15
	contentTypeHandshake        byte = 0x16
	contentTypeApplicationData  byte = 0x17

	// Handshake Type (RFC 5246 Section 7.4, RFC 8446 Section 4)
	handshakeTypeClientHello byte = 0x01
)

func parseRecordsAndHandshake(raw []byte, limits ParserLimits) ParseResult {
	if len(raw) < recordHeaderLen {
		return ParseResult{
			Status:      StatusNeedMoreData,
			BytesNeeded: recordHeaderLen - len(raw),
			Reason:      "record_header_incomplete",
		}
	}

	// 1. Initial ContentType and Version check
	firstContentType := raw[0]
	if firstContentType != contentTypeHandshake {
		if isKnownTLSContentType(firstContentType) {
			return ParseResult{
				Status: StatusNotClientHello,
				Reason: fmt.Sprintf("non_handshake_tls_content_type_0x%02x", firstContentType),
			}
		}
		return ParseResult{
			Status: StatusNotTLS,
			Reason: fmt.Sprintf("unrecognized_content_type_0x%02x", firstContentType),
		}
	}

	firstVersion := binary.BigEndian.Uint16(raw[1:3])
	if !isAcceptableRecordVersion(firstVersion) {
		return ParseResult{
			Status: StatusNotTLS,
			Reason: fmt.Sprintf("unsupported_record_version_0x%04x", firstVersion),
		}
	}

	// 2. Scan records and assemble logical handshake bytes
	var records []RecordBoundary
	var logicalHandshake []byte
	wireOffset := 0
	targetHandshakeLen := -1 // determined once we have 4 handshake header bytes

	for {
		if wireOffset >= len(raw) {
			if targetHandshakeLen > 0 && len(logicalHandshake) < targetHandshakeLen {
				// We need the next record's 5-byte header to make the next parsing decision
				return ParseResult{
					Status:      StatusNeedMoreData,
					BytesNeeded: recordHeaderLen,
					Reason:      "next_record_header_needed",
				}
			}
			break
		}

		remainingWire := len(raw) - wireOffset
		if remainingWire < recordHeaderLen {
			return ParseResult{
				Status:      StatusNeedMoreData,
				BytesNeeded: recordHeaderLen - remainingWire,
				Reason:      "record_header_incomplete",
			}
		}

		cType := raw[wireOffset]
		recVer := binary.BigEndian.Uint16(raw[wireOffset+1 : wireOffset+3])
		payloadLen := int(binary.BigEndian.Uint16(raw[wireOffset+3 : wireOffset+5]))

		// Validate record constraints
		if cType != contentTypeHandshake {
			return ParseResult{
				Status: StatusMalformed,
				Reason: fmt.Sprintf("unexpected_record_content_type_0x%02x_during_handshake", cType),
			}
		}
		if !isAcceptableRecordVersion(recVer) {
			return ParseResult{
				Status: StatusMalformed,
				Reason: fmt.Sprintf("inconsistent_record_version_0x%04x", recVer),
			}
		}
		if payloadLen > limits.MaxRecordPayloadBytes {
			return ParseResult{
				Status: StatusLimitExceeded,
				Reason: "record_payload_exceeds_rfc_limit",
			}
		}

		totalRecordWireLen := recordHeaderLen + payloadLen
		if totalRecordWireLen > limits.MaxWireRecordBytes {
			return ParseResult{
				Status: StatusLimitExceeded,
				Reason: "wire_record_exceeds_limit",
			}
		}

		if remainingWire < totalRecordWireLen {
			return ParseResult{
				Status:      StatusNeedMoreData,
				BytesNeeded: totalRecordWireLen - remainingWire,
				Reason:      "record_payload_incomplete",
			}
		}

		if len(records) >= limits.MaxRecordCount {
			return ParseResult{
				Status: StatusLimitExceeded,
				Reason: "record_count_exceeds_limit",
			}
		}

		recPayload := raw[wireOffset+recordHeaderLen : wireOffset+totalRecordWireLen]

		// Accumulate logical handshake bytes
		var consumedInRecord int
		var remainingInRecord int

		if targetHandshakeLen == -1 {
			// Handshake header not yet resolved.
			// Handshake header is 4 bytes: HandshakeType (1 byte) + uint24 Length (3 bytes)
			combined := append(logicalHandshake, recPayload...)
			if len(combined) < 4 {
				// Record payload was less than 4 bytes; accumulate and request next record
				logicalHandshake = combined
				records = append(records, RecordBoundary{
					WireOffset:       wireOffset,
					HeaderLen:        recordHeaderLen,
					PayloadLen:       payloadLen,
					PayloadConsumed:  payloadLen,
					PayloadRemaining: 0,
					Version:          recVer,
					ContentType:      cType,
				})
				wireOffset += totalRecordWireLen
				continue
			}

			// Validate HandshakeType
			hType := combined[0]
			if hType != handshakeTypeClientHello {
				return ParseResult{
					Status: StatusNotClientHello,
					Reason: fmt.Sprintf("handshake_type_0x%02x_not_client_hello", hType),
				}
			}

			declaredBodyLen := int(uint32(combined[1])<<16 | uint32(combined[2])<<8 | uint32(combined[3]))
			targetHandshakeLen = 4 + declaredBodyLen

			if targetHandshakeLen > limits.MaxHandshakeBytes {
				return ParseResult{
					Status: StatusLimitExceeded,
					Reason: "handshake_size_exceeds_limit",
				}
			}
		}

		needed := targetHandshakeLen - len(logicalHandshake)
		if len(recPayload) <= needed {
			consumedInRecord = len(recPayload)
			remainingInRecord = 0
			logicalHandshake = append(logicalHandshake, recPayload...)
		} else {
			// Record contains end of ClientHello followed by trailing data in same record
			consumedInRecord = needed
			remainingInRecord = len(recPayload) - needed
			logicalHandshake = append(logicalHandshake, recPayload[:consumedInRecord]...)
		}

		records = append(records, RecordBoundary{
			WireOffset:       wireOffset,
			HeaderLen:        recordHeaderLen,
			PayloadLen:       payloadLen,
			PayloadConsumed:  consumedInRecord,
			PayloadRemaining: remainingInRecord,
			Version:          recVer,
			ContentType:      cType,
		})

		wireOffset += totalRecordWireLen

		if len(logicalHandshake) == targetHandshakeLen {
			break
		}
	}

	// Check if handshake is complete
	if targetHandshakeLen == -1 || len(logicalHandshake) < targetHandshakeLen {
		return ParseResult{
			Status:      StatusNeedMoreData,
			BytesNeeded: recordHeaderLen,
			Reason:      "handshake_incomplete",
		}
	}

	// Calculate exact consumed wire bytes
	lastRec := records[len(records)-1]
	consumedWireBytes := lastRec.WireOffset + lastRec.HeaderLen + lastRec.PayloadConsumed
	hasTrailingData := lastRec.PayloadRemaining > 0 || len(raw) > consumedWireBytes

	meta := &ClientHelloMetadata{
		Records:                records,
		ConsumedWireBytes:      consumedWireBytes,
		LogicalHandshakeLength: len(logicalHandshake),
		IsFragmented:           len(records) > 1,
		HasTrailingData:        hasTrailingData,
	}

	// 3. Parse ClientHello body and extract SNI with bounds validation
	return parseClientHelloBody(logicalHandshake, meta)
}

func isKnownTLSContentType(b byte) bool {
	return b == contentTypeChangeCipherSpec ||
		b == contentTypeAlert ||
		b == contentTypeHandshake ||
		b == contentTypeApplicationData
}

// isAcceptableRecordVersion checks the legacy record-layer version in the outer header.
// Standard legacy record versions for ClientHello (RFC 8446 Appendix D.4 / RFC 5246):
// 0x0300 (SSL 3.0), 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2).
func isAcceptableRecordVersion(v uint16) bool {
	return v >= 0x0300 && v <= 0x0303
}

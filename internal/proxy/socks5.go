package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version = 0x05

	// Authentication methods
	socks5AuthNone         = 0x00
	socks5AuthNoAcceptable = 0xFF

	// Command codes
	socks5CmdConnect      = 0x01
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03

	// Address types
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	// Reply status codes
	socks5RepSuccess          = 0x00
	socks5RepGeneralFailure   = 0x01
	socks5RepNotAllowed       = 0x02
	socks5RepNetUnreachable   = 0x03
	socks5RepHostUnreachable  = 0x04
	socks5RepConnRefused      = 0x05
	socks5RepTTLExpired       = 0x06
	socks5RepCmdNotSupported  = 0x07
	socks5RepAtypNotSupported = 0x08
)

// HandleSOCKS5 processes a client SOCKS5 connection starting from the greeting.
func HandleSOCKS5(
	ctx context.Context,
	clientConn net.Conn,
	br *bufio.Reader,
	dialer Dialer,
	logger *slog.Logger,
	cfg HandlerConfig,
) error {
	// 1. Negotiation: Greeting & Auth Selection
	ver, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read SOCKS5 version: %w", err)
	}
	if ver != socks5Version {
		return fmt.Errorf("invalid SOCKS version 0x%02x; expected 0x05", ver)
	}

	nmethods, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read SOCKS5 nmethods: %w", err)
	}
	if nmethods == 0 {
		return errors.New("client offered zero auth methods")
	}

	methods := make([]byte, int(nmethods))
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read SOCKS5 methods: %w", err)
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == socks5AuthNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		// No acceptable authentication method found
		_, _ = clientConn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return errors.New("client does not support 'no authentication' mode")
	}

	// Send auth greeting response (0x05 0x00)
	if _, err := clientConn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
		return fmt.Errorf("write SOCKS5 auth response: %w", err)
	}

	// 2. Request Handling
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return fmt.Errorf("read SOCKS5 request header: %w", err)
	}

	reqVer := header[0]
	cmd := header[1]
	_ = header[2] // reserved (0x00)
	atyp := header[3]

	if reqVer != socks5Version {
		return fmt.Errorf("invalid SOCKS5 request version 0x%02x", reqVer)
	}

	if cmd != socks5CmdConnect {
		// BIND (0x02) and UDP ASSOCIATE (0x03) are explicitly unsupported in Phase 1
		sendSOCKS5Reply(clientConn, socks5RepCmdNotSupported)
		return fmt.Errorf("unsupported SOCKS5 command 0x%02x (only CONNECT 0x01 supported)", cmd)
	}

	var targetHost string
	switch atyp {
	case socks5AtypIPv4:
		ipv4Bytes := make([]byte, 4)
		if _, err := io.ReadFull(br, ipv4Bytes); err != nil {
			return fmt.Errorf("read IPv4 address: %w", err)
		}
		targetHost = net.IP(ipv4Bytes).String()

	case socks5AtypDomain:
		domainLen, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		if domainLen == 0 {
			sendSOCKS5Reply(clientConn, socks5RepGeneralFailure)
			return errors.New("empty domain name in SOCKS5 request")
		}
		domainBytes := make([]byte, int(domainLen))
		if _, err := io.ReadFull(br, domainBytes); err != nil {
			return fmt.Errorf("read domain name: %w", err)
		}
		targetHost = string(domainBytes)

	case socks5AtypIPv6:
		ipv6Bytes := make([]byte, 16)
		if _, err := io.ReadFull(br, ipv6Bytes); err != nil {
			return fmt.Errorf("read IPv6 address: %w", err)
		}
		targetHost = net.IP(ipv6Bytes).String()

	default:
		sendSOCKS5Reply(clientConn, socks5RepAtypNotSupported)
		return fmt.Errorf("unsupported address type 0x%02x", atyp)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return fmt.Errorf("read target port: %w", err)
	}
	targetPort := binary.BigEndian.Uint16(portBytes)
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	logger.Debug("socks5 connect target requested",
		TargetLogAttr(targetHost),
	)

	// 3. Dial Upstream
	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	upstreamConn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		logger.Warn("socks5 upstream connection failed",
			TargetLogAttr(targetHost),
			slog.String("error_category", ClassifyError(err)),
		)
		sendSOCKS5Reply(clientConn, socks5RepHostUnreachable)
		return fmt.Errorf("dial upstream %s: %w", targetAddr, err)
	}

	// 4. Send Success Reply
	if err := sendSOCKS5Reply(clientConn, socks5RepSuccess); err != nil {
		_ = upstreamConn.Close()
		return fmt.Errorf("send SOCKS5 success reply: %w", err)
	}

	// 5. Drain any pre-buffered client bytes
	var preBuffered []byte
	if br.Buffered() > 0 {
		preBuffered = make([]byte, br.Buffered())
		if _, err := io.ReadFull(br, preBuffered); err != nil {
			_ = upstreamConn.Close()
			return fmt.Errorf("drain pre-buffered bytes: %w", err)
		}
	}

	// 6. Enter Strategy Execution and Bidirectional Relay
	return ExecuteStrategyAndRelay(ctx, clientConn, upstreamConn, preBuffered, targetHost, logger, cfg)
}

// sendSOCKS5Reply writes a standard RFC 1928 SOCKS5 reply with 0.0.0.0:0 bound address.
func sendSOCKS5Reply(w io.Writer, repCode byte) error {
	reply := []byte{
		socks5Version,
		repCode,
		0x00,           // RSV
		socks5AtypIPv4, // ATYP: IPv4
		0, 0, 0, 0,     // BND.ADDR: 0.0.0.0
		0, 0, // BND.PORT: 0
	}
	_, err := w.Write(reply)
	return err
}

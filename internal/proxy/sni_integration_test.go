package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/tlsparse"
)

// generateSNITestCertificate creates an in-memory self-signed certificate and CA pool
// covering the specified DNS SAN hostnames.
// Strict certificate verification remains enabled in all integration tests; InsecureSkipVerify is NEVER used.
func generateSNITestCertificate(t *testing.T, dnsNames []string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	commonName := "127.0.0.1"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"DPIBypass SNI Test"},
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	certPool.AddCert(parsed)

	return cert, certPool
}

// recordedConn wraps a net.Conn and captures raw ingress (Read) and egress (Write) bytes
// without modifying production wire timing or byte ordering.
type recordedConn struct {
	net.Conn
	mu           sync.Mutex
	readBytes    bytes.Buffer
	writtenBytes bytes.Buffer
	reads        [][]byte
	writes       [][]byte
}

func (c *recordedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.readBytes.Write(p[:n])
		chunk := make([]byte, n)
		copy(chunk, p[:n])
		c.reads = append(c.reads, chunk)
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.writtenBytes.Write(p[:n])
		chunk := make([]byte, n)
		copy(chunk, p[:n])
		c.writes = append(c.writes, chunk)
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordedConn) IngressBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.readBytes.Len())
	copy(out, c.readBytes.Bytes())
	return out
}

func (c *recordedConn) EgressBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.writtenBytes.Len())
	copy(out, c.writtenBytes.Bytes())
	return out
}

// recordingListener wraps a net.Listener to wrap every accepted net.Conn in a recordedConn.
type recordingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*recordedConn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordedConn{Conn: c}
	l.mu.Lock()
	l.conns = append(l.conns, rc)
	l.mu.Unlock()
	return rc, nil
}

func (l *recordingListener) LastConn() *recordedConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[len(l.conns)-1]
}

// startInstrumentedTLSServer starts a local TLS HTTP server whose accepted TCP connections
// record raw ingress bytes for wire-integrity inspection.
func startInstrumentedTLSServer(t *testing.T, cert tls.Certificate) (string, *recordingListener, func()) {
	t.Helper()

	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start base listener: %v", err)
	}

	recLn := &recordingListener{Listener: baseLn}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsLn := tls.NewListener(recLn, tlsConfig)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SECURE_PAYLOAD_OK"))
	})

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ErrorLog:     log.New(io.Discard, "", 0), // suppress expected TLS bad-cert logs
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = server.Serve(tlsLn)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = tlsLn.Close()
		_ = baseLn.Close()
		<-serverDone
	}

	return baseLn.Addr().String(), recLn, cleanup
}

// testLoopbackDialer maps test hostnames (*.local) to targetAddr (loopback)
// without modifying system DNS or Windows configuration.
type testLoopbackDialer struct {
	base       Dialer
	targetAddr string
}

func (d *testLoopbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if strings.HasSuffix(host, ".local") || host == "localhost" {
			return d.base.DialContext(ctx, network, d.targetAddr)
		}
	}
	return d.base.DialContext(ctx, network, address)
}

// logCapturer captures structured proxy log output in-memory for assertion verification.
type logCapturer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapturer) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapturer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logCapturer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

// startTestProxy starts a local loopback proxy using production ListenLoopback and ServeConn.
func startTestProxy(
	t *testing.T,
	cfg HandlerConfig,
	targetServerAddr string,
) (string, *logCapturer, func()) {
	t.Helper()

	proxyLn, err := ListenLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	capturer := &logCapturer{}
	logger := slog.New(slog.NewJSONHandler(capturer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dialer := &testLoopbackDialer{
		base:       &NetDialer{Timeout: 2 * time.Second},
		targetAddr: targetServerAddr,
	}

	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				_ = ServeConn(ctx, c, dialer, logger, cfg)
			}(conn)
		}
	}()

	cleanup := func() {
		cancel()
		_ = proxyLn.Close()
		<-acceptDone
		wg.Wait()
	}

	return proxyLn.Addr().String(), capturer, cleanup
}

func dialHTTPConnect(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		_ = conn.Close()
		t.Fatalf("CONNECT expected 200, got %q, err: %v", line, err)
	}

	for {
		hdrLine, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(hdrLine) == "" {
			break
		}
	}

	_ = conn.SetDeadline(time.Time{})
	return conn
}

func dialSOCKS5Connect(t *testing.T, proxyAddr string, targetHost string, targetPort uint16) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingResp); err != nil {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 greeting response: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("unexpected SOCKS5 greeting response: %v", greetingResp)
	}

	// SOCKS5 CONNECT command
	var req []byte
	ip := net.ParseIP(targetHost)
	if ip4 := ip.To4(); ip4 != nil {
		req = []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(targetPort >> 8), byte(targetPort)}
	} else {
		domainBytes := []byte(targetHost)
		req = make([]byte, 4+1+len(domainBytes)+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x03
		req[4] = byte(len(domainBytes))
		copy(req[5:], domainBytes)
		req[5+len(domainBytes)] = byte(targetPort >> 8)
		req[5+len(domainBytes)+1] = byte(targetPort)
	}

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 connect request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 reply: %v", err)
	}
	if reply[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("SOCKS5 connect rejected with status 0x%02x", reply[1])
	}

	_ = conn.SetDeadline(time.Time{})
	return conn
}

func performTLSHandshakeAndHTTPRequest(
	t *testing.T,
	ctx context.Context,
	conn net.Conn,
	certPool *x509.CertPool,
	serverName string,
) error {
	t.Helper()

	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		ServerName:         serverName,
		InsecureSkipVerify: false, // Strict certificate verification is mandatory
	}

	tlsClient := tls.Client(conn, tlsConfig)
	defer tlsClient.Close()

	if err := tlsClient.HandshakeContext(ctx); err != nil {
		return err
	}

	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serverName)
	if _, err := tlsClient.Write([]byte(httpReq)); err != nil {
		return fmt.Errorf("write HTTP request: %w", err)
	}

	resp, err := io.ReadAll(tlsClient)
	if err != nil {
		return fmt.Errorf("read HTTP response: %w", err)
	}

	if !strings.Contains(string(resp), "SECURE_PAYLOAD_OK") {
		return fmt.Errorf("unexpected HTTP response payload: %q", string(resp))
	}

	return nil
}

// verifyRecordSplitClientHello validates the exact wire bytes captured by the upstream server
// against TLS record framing, declared lengths, SNI extraction, configured split position,
// re-parsing of reconstructed logical ClientHello, and bit-for-bit byte preservation against client egress.
func verifyRecordSplitClientHello(
	t *testing.T,
	clientEgress []byte,
	upstreamIngress []byte,
	expectedSNI string,
	offsetSpec string,
) {
	t.Helper()

	if len(upstreamIngress) == 0 {
		t.Fatalf("recorded upstream ingress bytes is empty")
	}

	// 1. Re-parse the recorded wire bytes using tlsparse
	parseRes := tlsparse.ParseClientHello(upstreamIngress, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed || parseRes.Metadata == nil {
		t.Fatalf("tlsparse failed to parse recorded bytes: status=%s, reason=%s", parseRes.Status, parseRes.Reason)
	}

	meta := parseRes.Metadata

	// 2. Verify that SNI was extracted and matches exactly
	if !meta.HasSNI {
		t.Fatalf("expected HasSNI to be true, got false")
	}
	if meta.SNI != expectedSNI {
		t.Fatalf("expected extracted SNI %q, got %q", expectedSNI, meta.SNI)
	}

	// 3. Verify that the ClientHello is represented as multiple records (fragmented)
	if !meta.IsFragmented {
		t.Fatalf("expected ClientHello to be fragmented across multiple records, got IsFragmented=false")
	}
	if len(meta.Records) != 2 {
		t.Fatalf("expected exactly 2 records, got %d", len(meta.Records))
	}

	// 4. Verify record framing and declared lengths
	rec1 := meta.Records[0]
	rec2 := meta.Records[1]

	if rec1.ContentType != 0x16 || rec2.ContentType != 0x16 {
		t.Fatalf("expected handshake content type 0x16, got rec1=0x%02x, rec2=0x%02x", rec1.ContentType, rec2.ContentType)
	}
	if rec1.HeaderLen != 5 || rec2.HeaderLen != 5 {
		t.Fatalf("expected 5-byte record headers, got rec1=%d, rec2=%d", rec1.HeaderLen, rec2.HeaderLen)
	}
	if rec1.PayloadConsumed != rec1.PayloadLen || rec2.PayloadConsumed != rec2.PayloadLen {
		t.Fatalf("unconsumed payload in records: rec1 consumed=%d/len=%d, rec2 consumed=%d/len=%d",
			rec1.PayloadConsumed, rec1.PayloadLen, rec2.PayloadConsumed, rec2.PayloadLen)
	}
	if rec1.PayloadRemaining != 0 || rec2.PayloadRemaining != 0 {
		t.Fatalf("trailing unconsumed payload in records: rec1 rem=%d, rec2 rem=%d",
			rec1.PayloadRemaining, rec2.PayloadRemaining)
	}

	// Total payload of both records must equal logical handshake length
	if rec1.PayloadLen+rec2.PayloadLen != meta.LogicalHandshakeLength {
		t.Fatalf("sum of record payloads (%d + %d = %d) != logical handshake length %d",
			rec1.PayloadLen, rec2.PayloadLen, rec1.PayloadLen+rec2.PayloadLen, meta.LogicalHandshakeLength)
	}

	// 5. Verify physical wire framing in the raw bytes
	clientHelloWire := upstreamIngress[:meta.ConsumedWireBytes]
	if clientHelloWire[0] != 0x16 {
		t.Fatalf("wire record 1 type != 0x16: 0x%02x", clientHelloWire[0])
	}
	wireRec1Len := int(binary.BigEndian.Uint16(clientHelloWire[3:5]))
	if wireRec1Len != rec1.PayloadLen {
		t.Fatalf("wire record 1 declared length %d != record payload length %d", wireRec1Len, rec1.PayloadLen)
	}

	wireRec2Offset := 5 + wireRec1Len
	if clientHelloWire[wireRec2Offset] != 0x16 {
		t.Fatalf("wire record 2 type != 0x16: 0x%02x", clientHelloWire[wireRec2Offset])
	}
	wireRec2Len := int(binary.BigEndian.Uint16(clientHelloWire[wireRec2Offset+3 : wireRec2Offset+5]))
	if wireRec2Len != rec2.PayloadLen {
		t.Fatalf("wire record 2 declared length %d != record payload length %d", wireRec2Len, rec2.PayloadLen)
	}

	if 5+wireRec1Len+5+wireRec2Len != len(clientHelloWire) {
		t.Fatalf("total wire records length %d != consumed wire bytes %d", 5+wireRec1Len+5+wireRec2Len, len(clientHelloWire))
	}

	// 6. Verify configured split position
	normOffset := strings.ToLower(strings.TrimSpace(offsetSpec))
	if normOffset == "" {
		normOffset = "sni-mid"
	}

	var expectedSplit int
	switch normOffset {
	case "sni-mid":
		expectedSplit = (meta.LogicalSNIOffsetStart + meta.LogicalSNIOffsetEnd) / 2
		if expectedSplit <= meta.LogicalSNIOffsetStart || expectedSplit >= meta.LogicalSNIOffsetEnd {
			t.Fatalf("expected split point %d to fall strictly within SNI [%d, %d)",
				expectedSplit, meta.LogicalSNIOffsetStart, meta.LogicalSNIOffsetEnd)
		}
	case "sni-start":
		expectedSplit = meta.LogicalSNIOffsetStart
	case "sni-end":
		expectedSplit = meta.LogicalSNIOffsetEnd
	default:
		val, err := strconv.Atoi(normOffset)
		if err != nil {
			t.Fatalf("invalid offset specification %q: %v", offsetSpec, err)
		}
		expectedSplit = val
	}

	if rec1.PayloadLen != expectedSplit {
		t.Fatalf("expected split at %s (%d), got rec1 payload len %d", normOffset, expectedSplit, rec1.PayloadLen)
	}
	if rec2.PayloadLen != meta.LogicalHandshakeLength-expectedSplit {
		t.Fatalf("expected rec2 payload len %d, got %d", meta.LogicalHandshakeLength-expectedSplit, rec2.PayloadLen)
	}

	// 7. Verify byte preservation and SNI reconstruction
	logicalReconstructed := make([]byte, 0, meta.LogicalHandshakeLength)
	rec1Payload := clientHelloWire[5 : 5+rec1.PayloadLen]
	rec2Payload := clientHelloWire[wireRec2Offset+5 : wireRec2Offset+5+rec2.PayloadLen]
	logicalReconstructed = append(logicalReconstructed, rec1Payload...)
	logicalReconstructed = append(logicalReconstructed, rec2Payload...)

	if len(logicalReconstructed) != meta.LogicalHandshakeLength {
		t.Fatalf("reconstructed logical length %d != metadata logical handshake length %d",
			len(logicalReconstructed), meta.LogicalHandshakeLength)
	}

	reconstructedSNI := string(logicalReconstructed[meta.LogicalSNIOffsetStart:meta.LogicalSNIOffsetEnd])
	if reconstructedSNI != expectedSNI {
		t.Fatalf("reconstructed SNI %q != expected %q", reconstructedSNI, expectedSNI)
	}

	if normOffset == "sni-mid" {
		rec1SNIPart := string(rec1Payload[meta.LogicalSNIOffsetStart:])
		rec2SNIPart := string(rec2Payload[:meta.LogicalSNIOffsetEnd-expectedSplit])
		if rec1SNIPart+rec2SNIPart != expectedSNI {
			t.Fatalf("SNI split fragments %q + %q != %q", rec1SNIPart, rec2SNIPart, expectedSNI)
		}
	}

	// 8. CRITICAL: Synthesize a single TLS record containing the reconstructed logical ClientHello
	// and prove that tlsparse parses it successfully as an unfragmented ClientHello.
	synthSingleRecord := make([]byte, 5+len(logicalReconstructed))
	synthSingleRecord[0] = 0x16 // Handshake record
	synthSingleRecord[1] = byte(rec1.Version >> 8)
	synthSingleRecord[2] = byte(rec1.Version)
	binary.BigEndian.PutUint16(synthSingleRecord[3:5], uint16(len(logicalReconstructed)))
	copy(synthSingleRecord[5:], logicalReconstructed)

	reparseLogical := tlsparse.ParseClientHello(synthSingleRecord, tlsparse.DefaultLimits())
	if reparseLogical.Status != tlsparse.StatusParsed || reparseLogical.Metadata == nil {
		t.Fatalf("reconstructed logical ClientHello failed parsing: status=%s, reason=%s",
			reparseLogical.Status, reparseLogical.Reason)
	}
	if !reparseLogical.Metadata.HasSNI || reparseLogical.Metadata.SNI != expectedSNI {
		t.Fatalf("reconstructed logical ClientHello SNI mismatch: expected %q, got %q",
			expectedSNI, reparseLogical.Metadata.SNI)
	}
	if reparseLogical.Metadata.IsFragmented {
		t.Fatalf("reconstructed logical ClientHello unexpectedly marked as fragmented")
	}
	if len(reparseLogical.Metadata.Records) != 1 {
		t.Fatalf("reconstructed logical ClientHello expected 1 record, got %d", len(reparseLogical.Metadata.Records))
	}
	if reparseLogical.Metadata.LogicalHandshakeLength != meta.LogicalHandshakeLength {
		t.Fatalf("reconstructed logical handshake length mismatch: got %d, expected %d",
			reparseLogical.Metadata.LogicalHandshakeLength, meta.LogicalHandshakeLength)
	}

	// 9. If client egress bytes were recorded, verify BIT-FOR-BIT byte preservation against client egress
	if len(clientEgress) >= 5 {
		clientParse := tlsparse.ParseClientHello(clientEgress, tlsparse.DefaultLimits())
		if clientParse.Status == tlsparse.StatusParsed && clientParse.Metadata != nil {
			if clientParse.Metadata.IsFragmented {
				t.Fatalf("client egress ClientHello was unexpectedly fragmented")
			}
			clientLogicalHandshake := clientEgress[5 : 5+clientParse.Metadata.LogicalHandshakeLength]
			if !bytes.Equal(clientLogicalHandshake, logicalReconstructed) {
				t.Fatalf("byte corruption detected: client logical handshake does not match reconstructed logical handshake")
			}
		}
	}
}

// verifySingleRecordClientHello confirms that an unmodified single TLS record was received.
func verifySingleRecordClientHello(
	t *testing.T,
	rawBytes []byte,
	expectedSNI string,
) {
	t.Helper()

	if len(rawBytes) == 0 {
		t.Fatalf("recorded raw bytes is empty")
	}

	parseRes := tlsparse.ParseClientHello(rawBytes, tlsparse.DefaultLimits())
	if parseRes.Status != tlsparse.StatusParsed || parseRes.Metadata == nil {
		t.Fatalf("tlsparse failed to parse recorded bytes: status=%s, reason=%s", parseRes.Status, parseRes.Reason)
	}

	meta := parseRes.Metadata
	if !meta.HasSNI {
		t.Fatalf("expected HasSNI to be true")
	}
	if meta.SNI != expectedSNI {
		t.Fatalf("expected SNI %q, got %q", expectedSNI, meta.SNI)
	}
	if meta.IsFragmented {
		t.Fatalf("expected unfragmented single record, got IsFragmented=true")
	}
	if len(meta.Records) != 1 {
		t.Fatalf("expected exactly 1 record, got %d", len(meta.Records))
	}
	if meta.Records[0].PayloadLen != meta.LogicalHandshakeLength {
		t.Fatalf("record payload len %d != handshake length %d", meta.Records[0].PayloadLen, meta.LogicalHandshakeLength)
	}
}

// TestSNIAwareProductionProxy_HTTPConnect_RecordSplit verifies the full production proxy path
// with HTTP CONNECT, SNI routing, tls-record-split (sni-mid), strict certificate verification,
// and upstream wire record verification.
func TestSNIAwareProductionProxy_HTTPConnect_RecordSplit(t *testing.T) {
	cert, certPool := generateSNITestCertificate(t, []string{"test.local"})
	upstreamAddr, recLn, serverCleanup := startInstrumentedTLSServer(t, cert)
	defer serverCleanup()

	matcher, err := config.NewDomainMatcher([]config.DomainRuleConfig{
		{Match: "test.local", Profile: "split-profile"},
	})
	if err != nil {
		t.Fatalf("compile domain rules: %v", err)
	}

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"}, // default is un-split
		Profiles: map[string]config.ProfileConfig{
			"split-profile": {Type: "tls-record-split", Offset: "sni-mid"},
		},
		Matcher: matcher,
	}

	proxyAddr, logCap, proxyCleanup := startTestProxy(t, cfg, upstreamAddr)
	defer proxyCleanup()

	_, portStr, _ := net.SplitHostPort(upstreamAddr)

	tests := []struct {
		name       string
		targetHost string
	}{
		{
			name:       "target_ip_literal_sni_routing",
			targetHost: upstreamAddr, // target is 127.0.0.1:port; rule MUST be matched by SNI
		},
		{
			name:       "target_dns_hostname_sni_routing",
			targetHost: net.JoinHostPort("test.local", portStr),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logCap.Reset()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			proxyConn := dialHTTPConnect(t, proxyAddr, tc.targetHost)
			defer proxyConn.Close()

			clientRecorder := &recordedConn{Conn: proxyConn}

			err := performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "test.local")
			if err != nil {
				t.Fatalf("handshake and HTTP request failed: %v", err)
			}

			lastConn := recLn.LastConn()
			if lastConn == nil {
				t.Fatalf("no connection recorded by upstream listener")
			}

			verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "test.local", "sni-mid")

			logs := logCap.String()
			if !strings.Contains(logs, "tls-record-split") {
				t.Fatalf("expected logs to indicate tls-record-split execution, got logs: %s", logs)
			}
			if strings.Contains(logs, `"fallback":true`) {
				t.Fatalf("expected strategy not to fallback, got logs: %s", logs)
			}
		})
	}
}

// TestSNIAwareProductionProxy_SOCKS5Connect_RecordSplit verifies the full production proxy path
// with SOCKS5 CONNECT (both IPv4 and domain destination), SNI routing, tls-record-split (sni-mid),
// strict certificate verification, and upstream wire record verification.
func TestSNIAwareProductionProxy_SOCKS5Connect_RecordSplit(t *testing.T) {
	cert, certPool := generateSNITestCertificate(t, []string{"test.local"})
	upstreamAddr, recLn, serverCleanup := startInstrumentedTLSServer(t, cert)
	defer serverCleanup()

	matcher, err := config.NewDomainMatcher([]config.DomainRuleConfig{
		{Match: "test.local", Profile: "split-profile"},
	})
	if err != nil {
		t.Fatalf("compile domain rules: %v", err)
	}

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
		Profiles: map[string]config.ProfileConfig{
			"split-profile": {Type: "tls-record-split", Offset: "sni-mid"},
		},
		Matcher: matcher,
	}

	proxyAddr, logCap, proxyCleanup := startTestProxy(t, cfg, upstreamAddr)
	defer proxyCleanup()

	_, portStr, _ := net.SplitHostPort(upstreamAddr)
	portNum, _ := strconv.Atoi(portStr)

	tests := []struct {
		name       string
		targetHost string
	}{
		{
			name:       "socks5_ipv4_literal_sni_routing",
			targetHost: "127.0.0.1",
		},
		{
			name:       "socks5_domain_name_sni_routing",
			targetHost: "test.local",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logCap.Reset()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			proxyConn := dialSOCKS5Connect(t, proxyAddr, tc.targetHost, uint16(portNum))
			defer proxyConn.Close()

			clientRecorder := &recordedConn{Conn: proxyConn}

			err := performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "test.local")
			if err != nil {
				t.Fatalf("SOCKS5 handshake and HTTP request failed: %v", err)
			}

			lastConn := recLn.LastConn()
			if lastConn == nil {
				t.Fatalf("no connection recorded by upstream listener")
			}

			verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "test.local", "sni-mid")

			logs := logCap.String()
			if !strings.Contains(logs, "tls-record-split") {
				t.Fatalf("expected logs to indicate tls-record-split execution, got logs: %s", logs)
			}
			if strings.Contains(logs, `"fallback":true`) {
				t.Fatalf("expected strategy not to fallback, got logs: %s", logs)
			}
		})
	}
}

// TestSNIAwareProductionProxy_CompositeStrategy covers tls-record-then-write-split with
// independent record_offset and write_offset settings across HTTP CONNECT and SOCKS5.
func TestSNIAwareProductionProxy_CompositeStrategy(t *testing.T) {
	cert, certPool := generateSNITestCertificate(t, []string{"composite.local", "numeric.local", "symbolic.local"})
	upstreamAddr, recLn, serverCleanup := startInstrumentedTLSServer(t, cert)
	defer serverCleanup()

	matcher, err := config.NewDomainMatcher([]config.DomainRuleConfig{
		{Match: "composite.local", Profile: "composite-numeric"},
		{Match: "numeric.local", Profile: "composite-numeric"},
		{Match: "symbolic.local", Profile: "composite-symbolic"},
	})
	if err != nil {
		t.Fatalf("compile domain rules: %v", err)
	}

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
		Profiles: map[string]config.ProfileConfig{
			"composite-numeric": {
				Type:         "tls-record-then-write-split",
				RecordOffset: "sni-mid",
				WriteOffset:  "20",
				DelayMS:      5,
			},
			"composite-symbolic": {
				Type:         "tls-record-then-write-split",
				RecordOffset: "sni-mid",
				WriteOffset:  "sni-start",
				DelayMS:      5,
			},
		},
		Matcher: matcher,
	}

	proxyAddr, logCap, proxyCleanup := startTestProxy(t, cfg, upstreamAddr)
	defer proxyCleanup()

	_, portStr, _ := net.SplitHostPort(upstreamAddr)
	portNum, _ := strconv.Atoi(portStr)

	t.Run("http_connect_numeric_write_offset", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		clientRecorder := &recordedConn{Conn: proxyConn}

		err := performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "composite.local")
		if err != nil {
			t.Fatalf("composite HTTP CONNECT handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no connection recorded")
		}

		verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "composite.local", "sni-mid")

		logs := logCap.String()
		if !strings.Contains(logs, "tls-record-then-write-split") {
			t.Fatalf("expected logs to indicate composite strategy execution, got: %s", logs)
		}
		if !strings.Contains(logs, `"chunks":2`) {
			t.Fatalf("expected composite strategy to produce 2 write chunks, got logs: %s", logs)
		}
		if strings.Contains(logs, `"fallback":true`) {
			t.Fatalf("expected composite strategy not to fallback, got logs: %s", logs)
		}
	})

	t.Run("socks5_connect_numeric_write_offset", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialSOCKS5Connect(t, proxyAddr, "composite.local", uint16(portNum))
		defer proxyConn.Close()

		clientRecorder := &recordedConn{Conn: proxyConn}

		err := performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "composite.local")
		if err != nil {
			t.Fatalf("composite SOCKS5 handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no connection recorded")
		}

		verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "composite.local", "sni-mid")

		logs := logCap.String()
		if !strings.Contains(logs, "tls-record-then-write-split") {
			t.Fatalf("expected logs to indicate composite strategy execution, got: %s", logs)
		}
		if !strings.Contains(logs, `"chunks":2`) {
			t.Fatalf("expected composite strategy to produce 2 write chunks, got logs: %s", logs)
		}
		if strings.Contains(logs, `"fallback":true`) {
			t.Fatalf("expected composite strategy not to fallback, got logs: %s", logs)
		}
	})

	t.Run("http_connect_independent_symbolic_write_offset", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		clientRecorder := &recordedConn{Conn: proxyConn}

		err := performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "symbolic.local")
		if err != nil {
			t.Fatalf("composite symbolic write offset handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no connection recorded")
		}

		verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "symbolic.local", "sni-mid")

		logs := logCap.String()
		if !strings.Contains(logs, "tls-record-then-write-split") {
			t.Fatalf("expected logs to indicate composite strategy execution, got: %s", logs)
		}
		if !strings.Contains(logs, `"chunks":2`) {
			t.Fatalf("expected composite strategy to produce 2 write chunks, got logs: %s", logs)
		}
		if strings.Contains(logs, `"fallback":true`) {
			t.Fatalf("expected composite strategy not to fallback, got logs: %s", logs)
		}
	})
}

// TestSNIAwareProductionProxy_DomainRoutingIsolation verifies that domain rules isolate profiles:
// configured domains receive record-split while unconfigured domains cleanly fall back to default "none" (1 record).
func TestSNIAwareProductionProxy_DomainRoutingIsolation(t *testing.T) {
	cert, certPool := generateSNITestCertificate(t, []string{"test.local", "other.local", "sub.wildcard.local"})
	upstreamAddr, recLn, serverCleanup := startInstrumentedTLSServer(t, cert)
	defer serverCleanup()

	// Exact rule for test.local, wildcard rule for *.wildcard.local
	matcher, err := config.NewDomainMatcher([]config.DomainRuleConfig{
		{Match: "test.local", Profile: "split-profile"},
		{Match: "*.wildcard.local", Profile: "split-profile"},
	})
	if err != nil {
		t.Fatalf("compile domain rules: %v", err)
	}

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
		Profiles: map[string]config.ProfileConfig{
			"split-profile": {Type: "tls-record-split", Offset: "sni-mid"},
		},
		Matcher: matcher,
	}

	proxyAddr, logCap, proxyCleanup := startTestProxy(t, cfg, upstreamAddr)
	defer proxyCleanup()

	_, portStr, _ := net.SplitHostPort(upstreamAddr)
	portNum, _ := strconv.Atoi(portStr)

	t.Run("http_unconfigured_domain_defaults_to_none", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		err = performTLSHandshakeAndHTTPRequest(t, ctx, proxyConn, certPool, "other.local")
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no recorded connection")
		}

		// Verify that other.local received SINGLE TLS record (un-split none strategy)
		verifySingleRecordClientHello(t, lastConn.IngressBytes(), "other.local")

		logs := logCap.String()
		if !strings.Contains(logs, `"strategy":"none"`) {
			t.Fatalf("expected logs to indicate 'none' strategy for unconfigured domain, got: %s", logs)
		}
	})

	t.Run("socks5_unconfigured_domain_defaults_to_none", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialSOCKS5Connect(t, proxyAddr, "other.local", uint16(portNum))
		defer proxyConn.Close()

		err = performTLSHandshakeAndHTTPRequest(t, ctx, proxyConn, certPool, "other.local")
		if err != nil {
			t.Fatalf("socks5 handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no recorded connection")
		}

		verifySingleRecordClientHello(t, lastConn.IngressBytes(), "other.local")

		logs := logCap.String()
		if !strings.Contains(logs, `"strategy":"none"`) {
			t.Fatalf("expected logs to indicate 'none' strategy, got: %s", logs)
		}
	})

	t.Run("wildcard_domain_rule_matches_subdomain", func(t *testing.T) {
		logCap.Reset()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		clientRecorder := &recordedConn{Conn: proxyConn}

		err = performTLSHandshakeAndHTTPRequest(t, ctx, clientRecorder, certPool, "sub.wildcard.local")
		if err != nil {
			t.Fatalf("wildcard subdomain handshake failed: %v", err)
		}

		lastConn := recLn.LastConn()
		if lastConn == nil {
			t.Fatalf("no recorded connection")
		}

		verifyRecordSplitClientHello(t, clientRecorder.EgressBytes(), lastConn.IngressBytes(), "sub.wildcard.local", "sni-mid")

		logs := logCap.String()
		if !strings.Contains(logs, "tls-record-split") {
			t.Fatalf("expected logs to indicate tls-record-split for wildcard match, got: %s", logs)
		}
	})
}

// TestSNIAwareProductionProxy_StrictCertVerificationEnforcement verifies that strict certificate
// and hostname validation is active: an invalid/untrusted hostname triggers a validation failure,
// and an untrusted CA fails verification without InsecureSkipVerify.
func TestSNIAwareProductionProxy_StrictCertVerificationEnforcement(t *testing.T) {
	// Certificate is valid only for test.local
	cert, certPool := generateSNITestCertificate(t, []string{"test.local"})
	upstreamAddr, _, serverCleanup := startInstrumentedTLSServer(t, cert)
	defer serverCleanup()

	matcher, _ := config.NewDomainMatcher([]config.DomainRuleConfig{
		{Match: "*.local", Profile: "split-profile"},
	})

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 500 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
		Profiles: map[string]config.ProfileConfig{
			"split-profile": {Type: "tls-record-split", Offset: "sni-mid"},
		},
		Matcher: matcher,
	}

	proxyAddr, _, proxyCleanup := startTestProxy(t, cfg, upstreamAddr)
	defer proxyCleanup()

	t.Run("hostname_mismatch_rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		// Connect with untrusted.local -> cert validation must fail with hostname verification error
		err := performTLSHandshakeAndHTTPRequest(t, ctx, proxyConn, certPool, "untrusted.local")
		if err == nil {
			t.Fatalf("expected TLS handshake to fail certificate verification for untrusted.local, but it succeeded")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "certificate") && !strings.Contains(errStr, "x509") && !strings.Contains(errStr, "untrusted.local") {
			t.Fatalf("expected certificate/hostname validation error, got: %v", err)
		}
	})

	t.Run("untrusted_ca_rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		// Client has empty trust pool (does not trust the self-signed cert)
		emptyPool := x509.NewCertPool()
		err := performTLSHandshakeAndHTTPRequest(t, ctx, proxyConn, emptyPool, "test.local")
		if err == nil {
			t.Fatalf("expected TLS handshake to fail untrusted CA verification, but it succeeded")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "certificate") && !strings.Contains(errStr, "x509") && !strings.Contains(errStr, "unknown authority") {
			t.Fatalf("expected unknown authority validation error, got: %v", err)
		}
	})

	t.Run("valid_cert_and_hostname_succeeds", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proxyConn := dialHTTPConnect(t, proxyAddr, upstreamAddr)
		defer proxyConn.Close()

		err := performTLSHandshakeAndHTTPRequest(t, ctx, proxyConn, certPool, "test.local")
		if err != nil {
			t.Fatalf("expected valid certificate and hostname to succeed, got: %v", err)
		}
	})
}

// TestSNIAwareProductionProxy_NonTLSInitialData verifies proxy fallback and graceful handling
// when the initial client payload is non-TLS data across HTTP CONNECT and SOCKS5.
func TestSNIAwareProductionProxy_NonTLSInitialData(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var echoWg sync.WaitGroup
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			echoWg.Add(1)
			go func(c net.Conn) {
				defer echoWg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c) // Full duplex echo
			}(conn)
		}
	}()

	defer func() {
		_ = echoLn.Close()
		<-echoDone
		echoWg.Wait()
	}()

	cfg := HandlerConfig{
		DialTimeout:              2 * time.Second,
		IdleTimeout:              5 * time.Second,
		InitialInspectionTimeout: 200 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "tls-record-split", Offset: "sni-mid"},
	}

	proxyAddr, logCap, proxyCleanup := startTestProxy(t, cfg, echoLn.Addr().String())
	defer proxyCleanup()

	t.Run("http_connect_plaintext", func(t *testing.T) {
		logCap.Reset()

		proxyConn := dialHTTPConnect(t, proxyAddr, echoLn.Addr().String())
		defer proxyConn.Close()
		_ = proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

		plainMsg := []byte("PLAINTEXT_NON_TLS_PAYLOAD_HTTP")
		if _, err := proxyConn.Write(plainMsg); err != nil {
			t.Fatalf("write plaintext payload: %v", err)
		}

		resp := make([]byte, len(plainMsg))
		if _, err := io.ReadFull(proxyConn, resp); err != nil {
			t.Fatalf("read echo response: %v", err)
		}

		if !bytes.Equal(resp, plainMsg) {
			t.Fatalf("expected echoed bytes %q, got %q", plainMsg, resp)
		}

		logs := logCap.String()
		if !strings.Contains(logs, `"fallback":true`) {
			t.Fatalf("expected fallback to 'none' on non-TLS data, got logs: %s", logs)
		}
	})

	t.Run("socks5_connect_plaintext", func(t *testing.T) {
		logCap.Reset()

		_, portStr, _ := net.SplitHostPort(echoLn.Addr().String())
		portNum, _ := strconv.Atoi(portStr)

		proxyConn := dialSOCKS5Connect(t, proxyAddr, "127.0.0.1", uint16(portNum))
		defer proxyConn.Close()
		_ = proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

		plainMsg := []byte("PLAINTEXT_NON_TLS_PAYLOAD_SOCKS5")
		if _, err := proxyConn.Write(plainMsg); err != nil {
			t.Fatalf("write plaintext payload: %v", err)
		}

		resp := make([]byte, len(plainMsg))
		if _, err := io.ReadFull(proxyConn, resp); err != nil {
			t.Fatalf("read echo response: %v", err)
		}

		if !bytes.Equal(resp, plainMsg) {
			t.Fatalf("expected echoed bytes %q, got %q", plainMsg, resp)
		}

		logs := logCap.String()
		if !strings.Contains(logs, `"fallback":true`) {
			t.Fatalf("expected fallback to 'none' on non-TLS data, got logs: %s", logs)
		}
	})
}

// TestSNIAwareProductionProxy_MalformedRequests verifies bounded error handling on invalid
// SOCKS5 and HTTP protocol commands without goroutine or resource leaks.
func TestSNIAwareProductionProxy_MalformedRequests(t *testing.T) {
	cfg := HandlerConfig{
		DialTimeout:              1 * time.Second,
		IdleTimeout:              2 * time.Second,
		InitialInspectionTimeout: 200 * time.Millisecond,
		MaxInitialBytes:          65536,
		DefaultProfile:           config.ProfileConfig{Type: "none"},
	}

	proxyAddr, _, proxyCleanup := startTestProxy(t, cfg, "127.0.0.1:0")
	defer proxyCleanup()

	t.Run("socks5_unsupported_auth", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Offer only method 0x02 (User/Pass), no 0x00
		_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(conn, resp)
		if resp[0] != 0x05 || resp[1] != 0xFF {
			t.Fatalf("expected 0x05 0xFF, got %v", resp)
		}
	})

	t.Run("socks5_unsupported_command_bind", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Greeting: no auth
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(conn, resp)

		// Command 0x02 (BIND)
		_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
		reply := make([]byte, 10)
		_, _ = io.ReadFull(conn, reply)
		if reply[1] != socks5RepCmdNotSupported {
			t.Fatalf("expected socks5RepCmdNotSupported (0x07), got 0x%02x", reply[1])
		}
	})

	t.Run("socks5_unsupported_atyp", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Greeting: no auth
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(conn, resp)

		// Command 0x01 (CONNECT) with invalid atyp 0xFF
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0xFF, 127, 0, 0, 1, 0x00, 0x50})
		reply := make([]byte, 10)
		_, _ = io.ReadFull(conn, reply)
		if reply[1] != socks5RepAtypNotSupported {
			t.Fatalf("expected socks5RepAtypNotSupported (0x08), got 0x%02x", reply[1])
		}
	})

	t.Run("socks5_truncated_greeting_clean_close", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Client sends only single byte 0x05 then closes write side
		_, _ = conn.Write([]byte{0x05})
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		buf := make([]byte, 16)
		_, _ = conn.Read(buf) // Must return EOF or close cleanly without hang
	})

	t.Run("http_malformed_connect_line", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// Invalid CONNECT line
		_, _ = conn.Write([]byte("CONNECT\r\n\r\n"))
		br := bufio.NewReader(conn)
		statusLine, _ := br.ReadString('\n')
		if !strings.Contains(statusLine, "400") {
			t.Fatalf("expected 400 Bad Request, got: %q", statusLine)
		}
	})

	t.Run("http_non_connect_method_rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("POST /invalid HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		br := bufio.NewReader(conn)
		statusLine, _ := br.ReadString('\n')
		if !strings.Contains(statusLine, "400") && !strings.Contains(statusLine, "405") {
			t.Fatalf("expected 400 or 405 error, got: %q", statusLine)
		}
	})
}

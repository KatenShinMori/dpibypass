//go:build windows && amd64

package divert

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"dpibypass/internal/config"
	"dpibypass/internal/dnsdoh"
	"dpibypass/internal/packetlab"
	"dpibypass/internal/strategy"
	"dpibypass/internal/tlsparse"
)

func TestFilterOutboundProductionSyntax(t *testing.T) {
	filter := FilterOutboundProduction

	// Refinement 1: Must strictly exclude port 53
	if strings.Contains(filter, "53") {
		t.Fatalf("VIOLATION: FilterOutboundProduction must NOT contain port 53, got %q", filter)
	}

	// Must contain target ports
	requiredClauses := []string{
		"outbound",
		"!impostor",
		"!loopback",
		"tcp.DstPort == 80",
		"tcp.DstPort == 443",
		"tcp.PayloadLength > 0",
		"udp and udp.DstPort == 443",
	}

	for _, req := range requiredClauses {
		if !strings.Contains(filter, req) {
			t.Errorf("FilterOutboundProduction missing required clause %q in %q", req, filter)
		}
	}
}

func TestFilterOutboundWithDNSSyntax(t *testing.T) {
	filter := FilterOutboundWithDNS

	requiredClauses := []string{
		"outbound",
		"!impostor",
		"!loopback",
		"tcp.DstPort == 80",
		"tcp.DstPort == 443",
		"tcp.PayloadLength > 0",
		"udp.DstPort == 443",
		"udp.DstPort == 53",
	}

	for _, req := range requiredClauses {
		if !strings.Contains(filter, req) {
			t.Errorf("FilterOutboundWithDNS missing required clause %q in %q", req, filter)
		}
	}
}

func TestFilterOutboundWithDNSEval(t *testing.T) {
	dll, err := syscall.LoadDLL(filepath.Join("..", "..", "WinDivert.dll"))
	if err != nil {
		t.Skipf("WinDivert.dll not available for eval test: %v", err)
	}
	defer dll.Release()

	evalFilterProc, err := dll.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatalf("FindProc EvalFilter: %v", err)
	}

	filter := FilterOutboundWithDNS
	filterPtr, _ := syscall.BytePtrFromString(filter)

	// Build raw IPv4 UDP port 53 packet
	udpLen := 8 + 12
	totalLen := 20 + udpLen
	udpPkt := make([]byte, totalLen)
	udpPkt[0] = 0x45
	binary.BigEndian.PutUint16(udpPkt[2:4], uint16(totalLen))
	udpPkt[8] = 64
	udpPkt[9] = 17 // UDP
	copy(udpPkt[12:16], []byte{192, 168, 1, 100})
	copy(udpPkt[16:20], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(udpPkt[20:22], 54321) // srcPort
	binary.BigEndian.PutUint16(udpPkt[22:24], 53)    // dstPort
	binary.BigEndian.PutUint16(udpPkt[24:26], uint16(udpLen))

	var addr Address
	addr.SetOutbound(true)
	addr.SetLoopback(false)
	addr.SetImpostor(false)
	addr.SetIPv6(false)

	rEval, _, _ := evalFilterProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&udpPkt[0])),
		uintptr(len(udpPkt)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if rEval == 0 {
		t.Errorf("FilterOutboundWithDNS failed to match UDP 53 packet! Evaluated to FALSE!")
	} else {
		t.Logf("FilterOutboundWithDNS successfully evaluated to TRUE on UDP 53 packet!")
	}

	// Verify impostor packet (e.g. re-injected by Kaspersky WFP) is also matched on UDP 53
	var impostorAddr Address
	impostorAddr.SetOutbound(true)
	impostorAddr.SetLoopback(false)
	impostorAddr.SetImpostor(true)
	impostorAddr.SetIPv6(false)

	rImpostorEval, _, _ := evalFilterProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&udpPkt[0])),
		uintptr(len(udpPkt)),
		uintptr(unsafe.Pointer(&impostorAddr)),
	)
	if rImpostorEval == 0 {
		t.Errorf("FilterOutboundWithDNS failed to match UDP 53 packet with impostor=true! Evaluated to FALSE!")
	} else {
		t.Logf("FilterOutboundWithDNS successfully evaluated to TRUE on UDP 53 packet with impostor=true!")
	}

	// Build raw inbound IPv4 UDP port 53 reply packet (SrcPort=53, DstPort=54321)
	// Inbound packets must NOT be captured by the outbound WinDivert filter handle.
	inboundPkt := make([]byte, totalLen)
	copy(inboundPkt, udpPkt)
	binary.BigEndian.PutUint16(inboundPkt[20:22], 53)    // srcPort = 53
	binary.BigEndian.PutUint16(inboundPkt[22:24], 54321) // dstPort = 54321
	var inboundAddr Address
	inboundAddr.SetOutbound(false)
	inboundAddr.SetLoopback(false)
	inboundAddr.SetImpostor(false)
	inboundAddr.SetIPv6(false)

	rInboundEval, _, _ := evalFilterProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&inboundPkt[0])),
		uintptr(len(inboundPkt)),
		uintptr(unsafe.Pointer(&inboundAddr)),
	)
	if rInboundEval != 0 {
		t.Errorf("FilterOutboundWithDNS unexpectedly matched inbound UDP 53 reply! Evaluated to TRUE!")
	} else {
		t.Logf("FilterOutboundWithDNS correctly ignored inbound UDP 53 reply (evaluated to FALSE).")
	}
}

func TestMaxPacketBufferSizeConstant(t *testing.T) {
	// Refinement 2: 64 KiB buffer sizing for LSO/TSO & Post-Quantum ClientHellos
	if MaxPacketBufferSize != 65535 {
		t.Fatalf("MaxPacketBufferSize must be exactly 65535 (0xFFFF), got %d", MaxPacketBufferSize)
	}
}

func TestFastPathZeroAllocations(t *testing.T) {
	// Construct synthetic IPv4 TCP packet with non-TLS payload (0x17)
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.Payload = []byte{0x17, 0x03, 0x03, 0x00, 0x20} // Application Data (non-handshake)

	pktNonTLS, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build non-TLS packet: %v", err)
	}

	// Pre-warm function
	action, _ := FastPathInspect(pktNonTLS)
	if action != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath, got %s", action)
	}

	// Refinement 3: Verify zero heap allocations on fast-path inspection
	allocs := testing.AllocsPerRun(1000, func() {
		act, _ := FastPathInspect(pktNonTLS)
		if act != ActionPassFastPath {
			t.Fatal("unexpected action")
		}
	})

	if allocs > 0 {
		t.Fatalf("FastPathInspect allocated %f heap objects per run; want 0", allocs)
	}

	// Also verify zero allocations for candidate TLS Handshake packet (0x16)
	cfgTLS := packetlab.DefaultPacketConfig()
	cfgTLS.DstPort = 443
	cfgTLS.Payload = []byte{0x16, 0x03, 0x01, 0x00, 0xA0} // TLS ClientHello header

	pktTLS, err := packetlab.BuildIPv4TCPPacket(cfgTLS)
	if err != nil {
		t.Fatalf("build TLS packet: %v", err)
	}

	allocsTLS := testing.AllocsPerRun(1000, func() {
		act, _ := FastPathInspect(pktTLS)
		if act != ActionInspectCandidate {
			t.Fatal("unexpected action")
		}
	})

	if allocsTLS > 0 {
		t.Fatalf("FastPathInspect (TLS candidate) allocated %f heap objects per run; want 0", allocsTLS)
	}
}

func TestFastPathDecisions(t *testing.T) {
	// 1. IPv4 TCP 443 TLS Handshake (0x16) -> ActionInspectCandidate
	cfg1 := packetlab.DefaultPacketConfig()
	cfg1.DstPort = 443
	cfg1.Payload = []byte{0x16, 0x03, 0x01, 0x01, 0x00}
	pkt1, _ := packetlab.BuildIPv4TCPPacket(cfg1)
	if act, _ := FastPathInspect(pkt1); act != ActionInspectCandidate {
		t.Errorf("TCP 443 TLS: got %s, want ActionInspectCandidate", act)
	}

	// 2. IPv4 TCP 443 Non-Handshake (0x17) -> ActionPassFastPath
	cfg2 := packetlab.DefaultPacketConfig()
	cfg2.DstPort = 443
	cfg2.Payload = []byte{0x17, 0x03, 0x03, 0x01, 0x00}
	pkt2, _ := packetlab.BuildIPv4TCPPacket(cfg2)
	if act, _ := FastPathInspect(pkt2); act != ActionPassFastPath {
		t.Errorf("TCP 443 AppData: got %s, want ActionPassFastPath", act)
	}

	// 3. IPv4 TCP 80 HTTP GET -> ActionInspectCandidate
	cfg3 := packetlab.DefaultPacketConfig()
	cfg3.DstPort = 80
	cfg3.Payload = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	pkt3, _ := packetlab.BuildIPv4TCPPacket(cfg3)
	if act, _ := FastPathInspect(pkt3); act != ActionInspectCandidate {
		t.Errorf("TCP 80 HTTP GET: got %s, want ActionInspectCandidate", act)
	}

	// 4. IPv4 TCP 80 Non-HTTP -> ActionPassFastPath
	cfg4 := packetlab.DefaultPacketConfig()
	cfg4.DstPort = 80
	cfg4.Payload = []byte{0x00, 0x01, 0x02, 0x03}
	pkt4, _ := packetlab.BuildIPv4TCPPacket(cfg4)
	if act, _ := FastPathInspect(pkt4); act != ActionPassFastPath {
		t.Errorf("TCP 80 binary: got %s, want ActionPassFastPath", act)
	}

	// 5. IPv4 TCP other port (e.g. 22 or 8080) -> ActionPassFastPath
	cfg5 := packetlab.DefaultPacketConfig()
	cfg5.DstPort = 8080
	cfg5.Payload = []byte("GET / HTTP/1.1\r\n")
	pkt5, _ := packetlab.BuildIPv4TCPPacket(cfg5)
	if act, _ := FastPathInspect(pkt5); act != ActionPassFastPath {
		t.Errorf("TCP 8080: got %s, want ActionPassFastPath", act)
	}

	// 6. IPv4 UDP 443 -> ActionDropQUIC
	pktUDP443 := make([]byte, 28) // 20B IPv4 + 8B UDP
	pktUDP443[0] = 0x45           // IPv4, IHL=5
	pktUDP443[9] = 17             // UDP
	pktUDP443[20] = 0x12          // SrcPort hi
	pktUDP443[21] = 0x34          // SrcPort lo
	pktUDP443[22] = 0x01          // DstPort 443 (0x01BB) hi
	pktUDP443[23] = 0xBB          // DstPort 443 lo
	if act, _ := FastPathInspect(pktUDP443); act != ActionDropQUIC {
		t.Errorf("UDP 443: got %s, want ActionDropQUIC", act)
	}

	// 7. IPv4 UDP 53 (DNS) -> ActionInterceptDNS
	pktUDP53 := make([]byte, 28)
	pktUDP53[0] = 0x45
	pktUDP53[9] = 17
	pktUDP53[22] = 0x00
	pktUDP53[23] = 53
	if act, _ := FastPathInspect(pktUDP53); act != ActionInterceptDNS {
		t.Errorf("UDP 53: got %s, want ActionInterceptDNS", act)
	}

	// 7b. IPv4 UDP other port (e.g. 12345) -> ActionPassFastPath
	pktUDP12345 := make([]byte, 28)
	pktUDP12345[0] = 0x45
	pktUDP12345[9] = 17
	pktUDP12345[22] = 0x30
	pktUDP12345[23] = 0x39
	if act, _ := FastPathInspect(pktUDP12345); act != ActionPassFastPath {
		t.Errorf("UDP 12345: got %s, want ActionPassFastPath", act)
	}

	// 8. IPv6 UDP 443 -> ActionDropQUIC
	pktIPv6UDP := make([]byte, 48) // 40B IPv6 + 8B UDP
	pktIPv6UDP[0] = 0x60           // IPv6 version 6
	pktIPv6UDP[6] = 17             // NextHeader = UDP
	pktIPv6UDP[40] = 0x12
	pktIPv6UDP[41] = 0x34
	pktIPv6UDP[42] = 0x01 // DstPort 443 hi
	pktIPv6UDP[43] = 0xBB // DstPort 443 lo
	if act, _ := FastPathInspect(pktIPv6UDP); act != ActionDropQUIC {
		t.Errorf("IPv6 UDP 443: got %s, want ActionDropQUIC", act)
	}

	// 9. IPv6 UDP 53 (DNS) -> ActionDropDNSIPv6
	pktIPv6UDP53 := make([]byte, 48)
	pktIPv6UDP53[0] = 0x60
	pktIPv6UDP53[6] = 17
	pktIPv6UDP53[42] = 0x00
	pktIPv6UDP53[43] = 53
	if act, _ := FastPathInspect(pktIPv6UDP53); act != ActionDropDNSIPv6 {
		t.Errorf("IPv6 UDP 53: got %s, want ActionDropDNSIPv6", act)
	}

	// 10. IPv6 TCP 443 -> ActionDropIPv6TCP
	pktIPv6TCP443 := make([]byte, 60)
	pktIPv6TCP443[0] = 0x60
	pktIPv6TCP443[6] = 6
	pktIPv6TCP443[40] = 0x12
	pktIPv6TCP443[41] = 0x34
	pktIPv6TCP443[42] = 0x01
	pktIPv6TCP443[43] = 0xBB
	if act, _ := FastPathInspect(pktIPv6TCP443); act != ActionDropIPv6TCP {
		t.Errorf("IPv6 TCP 443: got %s, want ActionDropIPv6TCP", act)
	}

	// 11. IPv6 TCP 80 -> ActionDropIPv6TCP
	pktIPv6TCP80 := make([]byte, 60)
	pktIPv6TCP80[0] = 0x60
	pktIPv6TCP80[6] = 6
	pktIPv6TCP80[42] = 0x00
	pktIPv6TCP80[43] = 80
	if act, _ := FastPathInspect(pktIPv6TCP80); act != ActionDropIPv6TCP {
		t.Errorf("IPv6 TCP 80: got %s, want ActionDropIPv6TCP", act)
	}

	// 12. IPv6 TCP non-target port (12345) -> ActionPassFastPath
	pktIPv6TCPOther := make([]byte, 60)
	pktIPv6TCPOther[0] = 0x60
	pktIPv6TCPOther[6] = 6
	binary.BigEndian.PutUint16(pktIPv6TCPOther[42:44], 12345)
	if act, _ := FastPathInspect(pktIPv6TCPOther); act != ActionPassFastPath {
		t.Errorf("IPv6 TCP 12345: got %s, want ActionPassFastPath", act)
	}
}

func TestFastPathIPv6DNSInterception(t *testing.T) {
	pktIPv6DNS := make([]byte, 48)
	pktIPv6DNS[0] = 0x60
	pktIPv6DNS[6] = 17
	pktIPv6DNS[40] = 0x50
	pktIPv6DNS[41] = 0x00
	pktIPv6DNS[42] = 0x00
	pktIPv6DNS[43] = 53

	// A. With InterceptDNS = true: packet dropped (ActionDropDNSIPv6, nil packet)
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	act, out, err := h.ProcessPacket(pktIPv6DNS, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket IPv6 DNS: %v", err)
	}
	if act != ActionDropDNSIPv6 {
		t.Fatalf("expected ActionDropDNSIPv6, got %s", act)
	}
	if out != nil {
		t.Fatalf("expected nil out packet for dropped IPv6 DNS leak, got %d bytes", len(out))
	}
	dnsIntercepted, _, _ := h.DNSStats()
	if dnsIntercepted != 1 {
		t.Fatalf("expected DNSQueriesIntercepted = 1, got %d", dnsIntercepted)
	}

	// B. With InterceptDNS = false: packet passes through unmodified
	cfgNoDNS := DefaultHarnessConfig()
	cfgNoDNS.InterceptDNS = false
	hNoDNS := NewHarness(cfgNoDNS)

	actNo, outNo, errNo := hNoDNS.ProcessPacket(pktIPv6DNS, &addr)
	if errNo != nil {
		t.Fatalf("ProcessPacket IPv6 DNS without interception: %v", errNo)
	}
	if actNo != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath, got %s", actNo)
	}
	if len(outNo) != len(pktIPv6DNS) {
		t.Fatalf("expected pass through packet length %d, got %d", len(pktIPv6DNS), len(outNo))
	}
}

func TestFastPathIPv6TCPDrop(t *testing.T) {
	pktIPv6TCP := make([]byte, 60)
	pktIPv6TCP[0] = 0x60
	pktIPv6TCP[6] = 6
	pktIPv6TCP[42] = 0x01
	pktIPv6TCP[43] = 0xBB // DstPort 443

	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	act, out, err := h.ProcessPacket(pktIPv6TCP, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket IPv6 TCP: %v", err)
	}
	if act != ActionDropIPv6TCP {
		t.Fatalf("expected ActionDropIPv6TCP, got %s", act)
	}
	if out != nil {
		t.Fatalf("expected nil out packet for dropped IPv6 TCP leak, got %d bytes", len(out))
	}
}

func TestHarnessProcessPacketInMemory(t *testing.T) {
	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)
	addr.SetTCPChecksum(true)

	// A. UDP 443 packet -> ActionDropQUIC (dropped, returns nil packet)
	pktUDP443 := make([]byte, 28)
	pktUDP443[0] = 0x45
	pktUDP443[9] = 17
	pktUDP443[22] = 0x01
	pktUDP443[23] = 0xBB

	act1, out1, err1 := h.ProcessPacket(pktUDP443, &addr)
	if err1 != nil {
		t.Fatalf("ProcessPacket UDP 443: %v", err1)
	}
	if act1 != ActionDropQUIC {
		t.Fatalf("expected ActionDropQUIC, got %s", act1)
	}
	if out1 != nil {
		t.Fatalf("expected nil out packet for dropped QUIC, got %d bytes", len(out1))
	}

	// B. Fast-path packet (TCP 443 with 0x17 Application Data) -> re-injected intact
	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 443
	pktCfg.Payload = []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0xAA, 0xBB}
	pktNonTLS, _ := packetlab.BuildIPv4TCPPacket(pktCfg)

	act2, out2, err2 := h.ProcessPacket(pktNonTLS, &addr)
	if err2 != nil {
		t.Fatalf("ProcessPacket TCP AppData: %v", err2)
	}
	if act2 != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath, got %s", act2)
	}
	if len(out2) != len(pktNonTLS) {
		t.Fatalf("output packet modified on fast path: got %d bytes, want %d", len(out2), len(pktNonTLS))
	}

	// C. Candidate TLS ClientHello packet -> ActionInspectCandidate
	pktCfgTLS := packetlab.DefaultPacketConfig()
	pktCfgTLS.DstPort = 443
	pktCfgTLS.Payload = []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}
	pktTLS, _ := packetlab.BuildIPv4TCPPacket(pktCfgTLS)

	act3, out3, err3 := h.ProcessPacket(pktTLS, &addr)
	if err3 != nil {
		t.Fatalf("ProcessPacket TLS candidate: %v", err3)
	}
	if act3 != ActionInspectCandidate {
		t.Fatalf("expected ActionInspectCandidate, got %s", act3)
	}
	if len(out3) != len(pktTLS) {
		t.Fatalf("output packet modified on default candidate pass: got %d bytes, want %d", len(out3), len(pktTLS))
	}

	// Verify stats counters
	recv, sent, quicDrop, fastPath, candidate := h.Stats()
	if recv != 3 {
		t.Errorf("Stats PacketsRecv = %d, want 3", recv)
	}
	if quicDrop != 1 {
		t.Errorf("Stats QUICDropped = %d, want 1", quicDrop)
	}
	if fastPath != 1 {
		t.Errorf("Stats TCPFastPath = %d, want 1", fastPath)
	}
	if candidate != 1 {
		t.Errorf("Stats TCPCandidate = %d, want 1", candidate)
	}
	if sent != 2 { // 1 fast-path + 1 candidate = 2 sent (QUIC was dropped)
		t.Errorf("Stats PacketsSent = %d, want 2", sent)
	}
}

type mockCandidateHandler struct {
	invoked bool
}

func (m *mockCandidateHandler) HandleCandidate(packet []byte, addr *Address, payloadOffset int) ([]byte, error) {
	m.invoked = true
	return packet, nil
}

func TestHarnessCustomCandidateHandler(t *testing.T) {
	mockH := &mockCandidateHandler{}
	cfg := DefaultHarnessConfig()
	cfg.Handler = mockH
	h := NewHarness(cfg)

	var addr Address
	pktCfgTLS := packetlab.DefaultPacketConfig()
	pktCfgTLS.DstPort = 443
	pktCfgTLS.Payload = []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01}
	pktTLS, _ := packetlab.BuildIPv4TCPPacket(pktCfgTLS)

	act, _, err := h.ProcessPacket(pktTLS, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if act != ActionInspectCandidate {
		t.Fatalf("expected ActionInspectCandidate, got %s", act)
	}
	if !mockH.invoked {
		t.Fatal("expected custom PacketHandler to be invoked for candidate packet")
	}
}

func TestLiveDriverHarness(t *testing.T) {
	// Graceful handling of driver in tests vs live runs:
	// If WinDivert.dll is not available or current process is not elevated,
	// skip cleanly with explanation without failing or crashing.
	if !IsAvailable() {
		t.Skip("skipping live WinDivert driver test: WinDivert.dll not available in test environment")
	}

	elevated, err := IsElevated()
	if err != nil || !elevated {
		t.Skip("skipping live WinDivert driver test: administrative elevation required to open driver")
	}

	// If available and elevated, verify loopback handle opening and clean close
	cfg := HarnessConfig{
		Filter:    FilterLoopbackTest,
		Priority:  0,
		QueueLen:  ParamQueueLengthDefault,
		QueueTime: ParamQueueTimeDefault,
		QueueSize: ParamQueueSizeDefault,
	}

	h := NewHarness(cfg)
	if err := h.Start(); err != nil {
		t.Fatalf("failed to start live harness on loopback test filter: %v", err)
	}

	if h.Handle() == InvalidHandle {
		t.Fatal("expected valid WinDivert handle after Start()")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- h.Run(ctx)
	}()

	<-ctx.Done()
	_ = h.Close()

	runErr := <-runErrCh
	if runErr != nil && runErr != context.Canceled && runErr != context.DeadlineExceeded {
		t.Fatalf("Harness.Run failed with unexpected error: %v", runErr)
	}
}

// ============================================================================
// Milestone 2.2: Deterministic Tests & Test Infrastructure
// ============================================================================

type SentCall struct {
	Packet []byte
	Addr   Address
}

type MockPacketSender struct {
	mu            sync.Mutex
	calls         []SentCall
	totalAttempts int
	failOnCall    int
	errToReturn   error
}

func (m *MockPacketSender) Send(packet []byte, addr *Address) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalAttempts++
	if m.failOnCall > 0 && m.totalAttempts == m.failOnCall {
		if m.errToReturn != nil {
			return 0, m.errToReturn
		}
		return 0, errors.New("mock send injected failure")
	}

	clonedPkt := append([]byte(nil), packet...)
	var clonedAddr Address
	if addr != nil {
		clonedAddr = *addr
	}
	m.calls = append(m.calls, SentCall{Packet: clonedPkt, Addr: clonedAddr})
	return len(packet), nil
}

func (m *MockPacketSender) Calls() []SentCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]SentCall, len(m.calls))
	copy(res, m.calls)
	return res
}

func (m *MockPacketSender) TotalAttempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalAttempts
}

type mockDomainMatcher struct {
	matchResult map[string]string
}

func (m *mockDomainMatcher) Match(domain string) (string, bool) {
	if prof, ok := m.matchResult[domain]; ok {
		return prof, true
	}
	return "", false
}

// buildTestClientHello constructs a structurally valid TLS 1.2/1.3 ClientHello record with SNI.
func buildTestClientHello(sni string) []byte {
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
		listLen := uint16(1 + 2 + len(sni))
		_ = binary.Write(&sniData, binary.BigEndian, listLen)
		sniData.WriteByte(0x00) // host_name (0x00)
		_ = binary.Write(&sniData, binary.BigEndian, uint16(len(sni)))
		sniData.WriteString(sni)

		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x0000))
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(sniData.Len()))
		extensionsBuf.Write(sniData.Bytes())
	}

	// Supported Groups extension (0x000A) ensuring SNI is not trailing the handshake
	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x000A))
	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(4))
	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(2))
	_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x001D))

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

	// Wrap in TLS Record Header (5 bytes: 0x16, 0x0301, length)
	record := bytes.Buffer{}
	record.WriteByte(0x16)
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(fullHandshake.Len()))
	record.Write(fullHandshake.Bytes())

	return record.Bytes()
}

func buildTestIPv4TCPClientHelloPacket(t *testing.T, sni string, seq uint32) []byte {
	t.Helper()
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.SeqNum = seq
	cfg.AckNum = 2000
	cfg.TCPFlags = packetlab.TCPFlagACK | packetlab.TCPFlagPSH
	cfg.Payload = buildTestClientHello(sni)

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build test IPv4 TCP ClientHello packet: %v", err)
	}
	return pkt
}

func TestOutOfOrderEmissionSequence(t *testing.T) {
	origSeq := uint32(50000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "example.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected exactly 2 split segments sent, got %d", len(calls))
	}

	// Parse both emitted packets
	segA, errA := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if errA != nil {
		t.Fatalf("parse first emitted segment: %v", errA)
	}
	segB, errB := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if errB != nil {
		t.Fatalf("parse second emitted segment: %v", errB)
	}

	// First emitted packet MUST be Segment 2 (higher SeqNum)
	// Second emitted packet MUST be Segment 1 (original SeqNum)
	if segB.SeqNum != origSeq {
		t.Errorf("second emitted packet (Segment 1) SeqNum = %d, want original %d", segB.SeqNum, origSeq)
	}
	expectedSeg2Seq := origSeq + uint32(len(segB.Payload))
	if segA.SeqNum != expectedSeg2Seq {
		t.Errorf("first emitted packet (Segment 2) SeqNum = %d, want %d", segA.SeqNum, expectedSeg2Seq)
	}

	// Verify stats
	handshakes, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 1 {
		t.Errorf("PacketsSplit = %d, want 1", split)
	}
	if injected != 2 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 2", injected)
	}
	if fallbacks != 0 {
		t.Errorf("PassThroughFallbacks = %d, want 0", fallbacks)
	}
	if sendErrors != 0 {
		t.Errorf("SendErrors = %d, want 0", sendErrors)
	}

	_, sent, _, _, candidate := h.Stats()
	if sent != 2 {
		t.Errorf("PacketsSent = %d, want 2", sent)
	}
	if candidate != 1 {
		t.Errorf("TCPCandidate = %d, want 1", candidate)
	}
}

func TestReassemblyReconstructsOriginalClientHelloByteForByte(t *testing.T) {
	origSeq := uint32(100000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "api.service.test", origSeq)

	origParsed, err := packetlab.ParseIPv4TCPPacket(pkt)
	if err != nil {
		t.Fatalf("parse original packet: %v", err)
	}

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	seg2Parsed, err2 := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err2 != nil {
		t.Fatalf("parse seg2: %v", err2)
	}
	seg1Parsed, err1 := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err1 != nil {
		t.Fatalf("parse seg1: %v", err1)
	}

	// Verify software checksums on both segments
	okIP1, errIP1 := packetlab.VerifyIPv4Checksum(calls[1].Packet)
	if !okIP1 || errIP1 != nil {
		t.Errorf("Segment 1 IPv4 checksum invalid: ok=%v, err=%v", okIP1, errIP1)
	}
	okTCP1, errTCP1 := packetlab.VerifyTCPChecksum(calls[1].Packet)
	if !okTCP1 || errTCP1 != nil {
		t.Errorf("Segment 1 TCP checksum invalid: ok=%v, err=%v", okTCP1, errTCP1)
	}

	okIP2, errIP2 := packetlab.VerifyIPv4Checksum(calls[0].Packet)
	if !okIP2 || errIP2 != nil {
		t.Errorf("Segment 2 IPv4 checksum invalid: ok=%v, err=%v", okIP2, errIP2)
	}
	okTCP2, errTCP2 := packetlab.VerifyTCPChecksum(calls[0].Packet)
	if !okTCP2 || errTCP2 != nil {
		t.Errorf("Segment 2 TCP checksum invalid: ok=%v, err=%v", okTCP2, errTCP2)
	}

	// Reassemble payloads in TCP sequence order: seg1 payload followed by seg2 payload
	reassembled := append([]byte(nil), seg1Parsed.Payload...)
	reassembled = append(reassembled, seg2Parsed.Payload...)

	if !bytes.Equal(reassembled, origParsed.Payload) {
		t.Fatalf("reassembled payload mismatch:\ngot  %x\nwant %x", reassembled, origParsed.Payload)
	}

	// Verify reassembled payload parses cleanly as a ClientHello
	reparse := tlsparse.ParseClientHello(reassembled, tlsparse.DefaultLimits())
	if reparse.Status != tlsparse.StatusParsed {
		t.Fatalf("reassembled payload failed TLS parsing: status=%s, reason=%s", reparse.Status, reparse.Reason)
	}
	if !reparse.Metadata.HasSNI || reparse.Metadata.SNI != "api.service.test" {
		t.Errorf("reassembled metadata SNI mismatch: got %q, want %q", reparse.Metadata.SNI, "api.service.test")
	}
}

func TestAddressChecksumValidityBits(t *testing.T) {
	pkt := buildTestIPv4TCPClientHelloPacket(t, "checksum-test.example", 1000)

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	// Input address has IPChecksum and TCPChecksum set to FALSE
	var addr Address
	addr.SetOutbound(true)
	addr.SetIPChecksum(false)
	addr.SetTCPChecksum(false)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 split segment calls, got %d", len(calls))
	}

	// Requirement: Cloned Address for split segments explicitly sets IPChecksum and TCPChecksum to true
	for i, c := range calls {
		if !c.Addr.IPChecksum() {
			t.Errorf("call[%d] Addr.IPChecksum() = false; want true for software-checksummed split segment", i)
		}
		if !c.Addr.TCPChecksum() {
			t.Errorf("call[%d] Addr.TCPChecksum() = false; want true for software-checksummed split segment", i)
		}
	}

	// Requirement: For pass-through packets, original captured Address bitfields remain untouched
	mockPass := &MockPacketSender{}
	hPass := NewHarness(DefaultHarnessConfig())

	var addrUntouched Address
	addrUntouched.SetOutbound(true)
	addrUntouched.SetIPChecksum(false)
	addrUntouched.SetTCPChecksum(false)

	// Send non-TLS fast-path packet
	cfgFast := packetlab.DefaultPacketConfig()
	cfgFast.DstPort = 443
	cfgFast.Payload = []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x01} // AppData (fast path)
	pktFast, _ := packetlab.BuildIPv4TCPPacket(cfgFast)

	if err := hPass.HandlePacket(pktFast, &addrUntouched, mockPass); err != nil {
		t.Fatalf("HandlePacket fast-path: %v", err)
	}

	passCalls := mockPass.Calls()
	if len(passCalls) != 1 {
		t.Fatalf("expected 1 pass-through call, got %d", len(passCalls))
	}

	if passCalls[0].Addr.IPChecksum() != false {
		t.Errorf("pass-through Addr.IPChecksum() was mutated to true; want false (untouched)")
	}
	if passCalls[0].Addr.TCPChecksum() != false {
		t.Errorf("pass-through Addr.TCPChecksum() was mutated to true; want false (untouched)")
	}
}

func TestSafePassThroughFallback_MalformedTLS(t *testing.T) {
	// Construct candidate packet (TCP 443, 0x16 prefix) with truncated/malformed TLS body
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.Payload = []byte{0x16, 0x03, 0x01, 0xFF, 0xFF, 0x00, 0x01} // Declared 65535 bytes, truncated to 2
	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket on malformed TLS should safely fall back, got error: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 fallback call, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback emitted packet does not match original packet")
	}

	handshakes, split, injected, fallbacks, _ := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if injected != 0 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 0", injected)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestSafePassThroughFallback_NonMatchingDomain(t *testing.T) {
	// Configure harness with specific target domains
	cfg := DefaultHarnessConfig()
	cfg.TargetDomains = []string{"blocked.com", "*.blocked.org"}

	mock := &MockPacketSender{}
	h := NewHarness(cfg)

	// Send ClientHello with un-targeted SNI
	pkt := buildTestIPv4TCPClientHelloPacket(t, "allowed.example.net", 2000)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback call for non-matching domain, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback packet does not match original packet")
	}

	_, split, _, fallbacks, _ := h.ExtendedStats()
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestSafePassThroughFallback_DomainMatchesNone(t *testing.T) {
	matcher := &mockDomainMatcher{
		matchResult: map[string]string{
			"passthrough.com": "none",
		},
	}
	cfg := DefaultHarnessConfig()
	cfg.DomainMatcher = matcher

	mock := &MockPacketSender{}
	h := NewHarness(cfg)

	pkt := buildTestIPv4TCPClientHelloPacket(t, "passthrough.com", 3000)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback call for 'none' profile, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback packet does not match original packet")
	}

	_, split, _, fallbacks, _ := h.ExtendedStats()
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestSafePassThroughFallback_NonIPv4(t *testing.T) {
	// Construct synthetic IPv6 TCP 443 candidate packet (40B IPv6 + 20B TCP + ClientHello)
	tlsPayload := buildTestClientHello("ipv6-test.com")
	pkt6 := make([]byte, 40+20+len(tlsPayload))
	pkt6[0] = 0x60                                 // IPv6
	pkt6[6] = 6                                    // NextHeader = TCP
	binary.BigEndian.PutUint16(pkt6[40:42], 12345) // SrcPort
	binary.BigEndian.PutUint16(pkt6[42:44], 443)   // DstPort = 443
	pkt6[52] = 0x50                                // TCP DataOffset = 5 (20 bytes)
	pkt6[53] = packetlab.TCPFlagACK
	copy(pkt6[60:], tlsPayload)

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)
	addr.SetIPv6(true)

	if err := h.HandlePacket(pkt6, &addr, mock); err != nil {
		t.Fatalf("HandlePacket on IPv6: %v", err)
	}

	// Per Root Cause 3, outbound IPv6 TCP 443 packets are immediately dropped (ActionDropIPv6TCP)
	// to prevent ISP blocking leaks and force client Happy Eyeballs fallback to IPv4 TCP.
	calls := mock.Calls()
	if len(calls) != 0 {
		t.Fatalf("expected 0 calls for dropped IPv6 candidate, got %d", len(calls))
	}

	_, split, _, _, _ := h.ExtendedStats()
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
}

func TestNonDuplicationOnSecondSendFailure(t *testing.T) {
	pkt := buildTestIPv4TCPClientHelloPacket(t, "failure-test.example", 5000)

	// Configure mock sender to succeed on Call 1 (Segment 2), but fail on Call 2 (Segment 1)
	injectedErr := errors.New("network drop on segment 1")
	mock := &MockPacketSender{
		failOnCall:  2,
		errToReturn: injectedErr,
	}

	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	err := h.HandlePacket(pkt, &addr, mock)
	if err == nil {
		t.Fatal("expected error from second Send call, got nil")
	}
	if !strings.Contains(err.Error(), "network drop on segment 1") {
		t.Fatalf("expected injected error in returned error, got %v", err)
	}

	// Requirement: Once Segment 2 has been transmitted, NEVER fall back to sending original packet!
	// Total attempts must be exactly 2 (Call 1: Seg2, Call 2: Seg1). No 3rd attempt for original packet!
	if mock.TotalAttempts() != 2 {
		t.Fatalf("TotalAttempts = %d; want 2 (duplicate send of original packet must NOT occur)", mock.TotalAttempts())
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("successful calls = %d; want 1 (only Segment 2 succeeded)", len(calls))
	}

	handshakes, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 1 {
		t.Errorf("PacketsSplit = %d, want 1", split)
	}
	if injected != 1 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 1", injected)
	}
	if fallbacks != 0 {
		t.Errorf("PassThroughFallbacks = %d; want 0 (fallback forbidden after partial transmission)", fallbacks)
	}
	if sendErrors != 1 {
		t.Errorf("SendErrors = %d, want 1", sendErrors)
	}
}

func TestInterPacketDelay(t *testing.T) {
	pkt := buildTestIPv4TCPClientHelloPacket(t, "delay-test.example", 8000)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.InterPacketDelay = 20 * time.Millisecond
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	start := time.Now()
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 15*time.Millisecond {
		t.Errorf("inter-packet delay elapsed %v, want >= 15ms", elapsed)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
}

func TestSafePassThroughFallback_FragmentedIPv4(t *testing.T) {
	origPkt := buildTestIPv4TCPClientHelloPacket(t, "fragmented.example", 4000)

	// Clone and set More Fragments (MF = 0x2000) in IPv4 flags
	pktFrag := append([]byte(nil), origPkt...)
	binary.BigEndian.PutUint16(pktFrag[6:8], 0x2000)
	// Recompute IPv4 checksum for the modified packet
	binary.BigEndian.PutUint16(pktFrag[10:12], 0)
	ihl := int(pktFrag[0]&0x0F) * 4
	binary.BigEndian.PutUint16(pktFrag[10:12], packetlab.IPv4Checksum(pktFrag[:ihl]))

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pktFrag, &addr, mock); err != nil {
		t.Fatalf("HandlePacket fragmented IPv4 should safely fall back, got error: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback call, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pktFrag) {
		t.Fatal("fallback packet did not match original fragmented packet")
	}

	handshakes, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if injected != 0 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 0", injected)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
	if sendErrors != 0 {
		t.Errorf("SendErrors = %d, want 0", sendErrors)
	}
}

func TestSafePassThroughFallback_PayloadTooShort(t *testing.T) {
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.Payload = []byte{0x16} // Only 1 byte (< 2 bytes cannot be split)

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket payload too short: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback call, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback packet mismatch")
	}

	handshakes, split, _, fallbacks, _ := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestPassThrough_Port80HTTP(t *testing.T) {
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 80
	cfg.Payload = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket port 80: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 pass-through call, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("pass-through packet mismatch")
	}

	handshakes, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 0 {
		t.Errorf("CandidateHandshakes = %d, want 0 (HTTP GET is not a TLS handshake)", handshakes)
	}
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if injected != 0 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 0", injected)
	}
	if fallbacks != 0 {
		t.Errorf("PassThroughFallbacks = %d, want 0 (normal HTTP GET is not a fallback)", fallbacks)
	}
	if sendErrors != 0 {
		t.Errorf("SendErrors = %d, want 0", sendErrors)
	}

	_, sent, _, _, candidate := h.Stats()
	if candidate != 1 {
		t.Errorf("TCPCandidate = %d, want 1", candidate)
	}
	if sent != 1 {
		t.Errorf("PacketsSent = %d, want 1", sent)
	}
}

func TestConfiguredSplitOffsets(t *testing.T) {
	cases := []struct {
		name      string
		splitSpec string
	}{
		{
			name:      "sni-start",
			splitSpec: "sni-start",
		},
		{
			name:      "sni-end",
			splitSpec: "sni-end",
		},
		{
			name:      "numeric-offset-5",
			splitSpec: "5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origSeq := uint32(200000)
			pkt := buildTestIPv4TCPClientHelloPacket(t, "custom-offset.example.com", origSeq)

			origParsed, err := packetlab.ParseIPv4TCPPacket(pkt)
			if err != nil {
				t.Fatalf("parse original packet: %v", err)
			}
			metaRes := tlsparse.ParseClientHello(origParsed.Payload, tlsparse.DefaultLimits())
			if metaRes.Status != tlsparse.StatusParsed {
				t.Fatalf("parse metadata: %s", metaRes.Reason)
			}

			mock := &MockPacketSender{}
			cfg := DefaultHarnessConfig()
			cfg.SplitOffset = tc.splitSpec
			cfg.Sender = mock
			h := NewHarness(cfg)

			var addr Address
			addr.SetOutbound(true)

			if err := h.HandlePacket(pkt, &addr, mock); err != nil {
				t.Fatalf("HandlePacket (%s): %v", tc.name, err)
			}

			calls := mock.Calls()
			if len(calls) != 2 {
				t.Fatalf("expected 2 calls, got %d", len(calls))
			}

			seg2Parsed, err2 := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
			if err2 != nil {
				t.Fatalf("parse seg2: %v", err2)
			}
			seg1Parsed, err1 := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
			if err1 != nil {
				t.Fatalf("parse seg1: %v", err1)
			}

			expectedSplitOffset, err := strategy.ResolveSplitOffset(origParsed.Payload, metaRes.Metadata, tc.splitSpec)
			if err != nil {
				t.Fatalf("ResolveSplitOffset (%s): %v", tc.name, err)
			}
			if len(seg1Parsed.Payload) != expectedSplitOffset {
				t.Errorf("seg1 payload len = %d, want %d", len(seg1Parsed.Payload), expectedSplitOffset)
			}

			// Segment 2 emitted first with higher SeqNum
			if seg1Parsed.SeqNum != origSeq {
				t.Errorf("seg1 SeqNum = %d, want %d", seg1Parsed.SeqNum, origSeq)
			}
			if seg2Parsed.SeqNum != origSeq+uint32(expectedSplitOffset) {
				t.Errorf("seg2 SeqNum = %d, want %d", seg2Parsed.SeqNum, origSeq+uint32(expectedSplitOffset))
			}

			// Byte-for-byte reassembly
			reassembled := append([]byte(nil), seg1Parsed.Payload...)
			reassembled = append(reassembled, seg2Parsed.Payload...)
			if !bytes.Equal(reassembled, origParsed.Payload) {
				t.Fatalf("reassembled payload mismatch for %s", tc.name)
			}
		})
	}
}

func TestPostQuantumClientHelloFragmentation(t *testing.T) {
	// Build large ClientHello with ~1800 bytes payload simulating post-quantum ML-KEM-768 key shares
	handshakeBody := bytes.Buffer{}
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x0303)) // TLS 1.2
	handshakeBody.Write(bytes.Repeat([]byte{0x42}, 32))                // Random
	handshakeBody.WriteByte(0x00)                                      // SessionID len 0

	// Cipher Suites
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(4))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x1301))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x1302))

	// Compression
	handshakeBody.WriteByte(0x01)
	handshakeBody.WriteByte(0x00)

	// Extensions
	extBuf := bytes.Buffer{}

	// SNI
	sni := "pq-kem.cloudflare.test"
	sniData := bytes.Buffer{}
	_ = binary.Write(&sniData, binary.BigEndian, uint16(1+2+len(sni)))
	sniData.WriteByte(0x00)
	_ = binary.Write(&sniData, binary.BigEndian, uint16(len(sni)))
	sniData.WriteString(sni)
	_ = binary.Write(&extBuf, binary.BigEndian, uint16(0x0000))
	_ = binary.Write(&extBuf, binary.BigEndian, uint16(sniData.Len()))
	extBuf.Write(sniData.Bytes())

	// Simulated ML-KEM-768 Key Share extension (type 0x0033 key_share, 1200 bytes)
	pqKeyShare := bytes.Repeat([]byte{0x77}, 1200)
	_ = binary.Write(&extBuf, binary.BigEndian, uint16(0x0033))
	_ = binary.Write(&extBuf, binary.BigEndian, uint16(len(pqKeyShare)))
	extBuf.Write(pqKeyShare)

	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(extBuf.Len()))
	handshakeBody.Write(extBuf.Bytes())

	// Wrap in ClientHello
	fullHandshake := bytes.Buffer{}
	fullHandshake.WriteByte(0x01)
	bLen := handshakeBody.Len()
	fullHandshake.WriteByte(byte(bLen >> 16))
	fullHandshake.WriteByte(byte(bLen >> 8))
	fullHandshake.WriteByte(byte(bLen & 0xFF))
	fullHandshake.Write(handshakeBody.Bytes())

	// Wrap in TLS Record
	record := bytes.Buffer{}
	record.WriteByte(0x16)
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(fullHandshake.Len()))
	record.Write(fullHandshake.Bytes())

	// Packet with 12 bytes TCP Options (NOP, NOP, TSopt 10 bytes: kind 8, len 10, tsval, tsecr)
	tcpOptions := []byte{
		0x01, 0x01, // NOP, NOP
		0x08, 0x0A, // Kind 8 (Timestamp), Len 10
		0x11, 0x22, 0x33, 0x44, // TSval
		0x55, 0x66, 0x77, 0x88, // TSecr
	}

	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.SeqNum = 500000
	cfg.AckNum = 700000
	cfg.TCPFlags = packetlab.TCPFlagACK | packetlab.TCPFlagPSH
	cfg.TCPOptions = tcpOptions
	cfg.Payload = record.Bytes()

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build PQ packet: %v", err)
	}

	mock := &MockPacketSender{}
	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket PQ ClientHello: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	// Verify both segments emitted
	seg2, err2 := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err2 != nil {
		t.Fatalf("parse seg2: %v", err2)
	}
	seg1, err1 := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err1 != nil {
		t.Fatalf("parse seg1: %v", err1)
	}

	// TCP options preserved
	if !bytes.Equal(seg1.TCPOptions, tcpOptions) {
		t.Errorf("seg1 TCPOptions mismatch: got %x, want %x", seg1.TCPOptions, tcpOptions)
	}
	if !bytes.Equal(seg2.TCPOptions, tcpOptions) {
		t.Errorf("seg2 TCPOptions mismatch: got %x, want %x", seg2.TCPOptions, tcpOptions)
	}

	// Reassembly
	reassembled := append([]byte(nil), seg1.Payload...)
	reassembled = append(reassembled, seg2.Payload...)
	if !bytes.Equal(reassembled, record.Bytes()) {
		t.Fatalf("PQ reassembled payload mismatch")
	}

	// Verify checksums
	okIP1, _ := packetlab.VerifyIPv4Checksum(calls[1].Packet)
	okTCP1, _ := packetlab.VerifyTCPChecksum(calls[1].Packet)
	okIP2, _ := packetlab.VerifyIPv4Checksum(calls[0].Packet)
	okTCP2, _ := packetlab.VerifyTCPChecksum(calls[0].Packet)
	if !okIP1 || !okTCP1 || !okIP2 || !okTCP2 {
		t.Errorf("checksums invalid: ip1=%v, tcp1=%v, ip2=%v, tcp2=%v", okIP1, okTCP1, okIP2, okTCP2)
	}

	// Verify offload bits
	if !calls[0].Addr.IPChecksum() || !calls[0].Addr.TCPChecksum() {
		t.Error("calls[0] offload bits not set")
	}
	if !calls[1].Addr.IPChecksum() || !calls[1].Addr.TCPChecksum() {
		t.Error("calls[1] offload bits not set")
	}
}

func TestFirstSendFailureDoesNotDuplicate(t *testing.T) {
	pkt := buildTestIPv4TCPClientHelloPacket(t, "first-failure.example", 9000)

	// Mock sender fails on Call 1 (Segment 2)
	injectedErr := errors.New("network drop on segment 2")
	mock := &MockPacketSender{
		failOnCall:  1,
		errToReturn: injectedErr,
	}

	h := NewHarness(DefaultHarnessConfig())

	var addr Address
	addr.SetOutbound(true)

	err := h.HandlePacket(pkt, &addr, mock)
	if err == nil {
		t.Fatal("expected error on segment 2 send failure, got nil")
	}
	if !strings.Contains(err.Error(), "network drop on segment 2") {
		t.Fatalf("expected injected error, got %v", err)
	}

	// Attempt count must be exactly 1: failed on seg2, no seg1, no original packet!
	if mock.TotalAttempts() != 1 {
		t.Fatalf("TotalAttempts = %d, want 1", mock.TotalAttempts())
	}
	if len(mock.Calls()) != 0 {
		t.Fatalf("successful calls = %d, want 0", len(mock.Calls()))
	}

	handshakes, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 1 {
		t.Errorf("PacketsSplit = %d, want 1", split)
	}
	if injected != 0 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 0", injected)
	}
	if fallbacks != 0 {
		t.Errorf("PassThroughFallbacks = %d, want 0", fallbacks)
	}
	if sendErrors != 1 {
		t.Errorf("SendErrors = %d, want 1", sendErrors)
	}
}

func TestFastPathSubsequentFragment(t *testing.T) {
	origPkt := buildTestIPv4TCPClientHelloPacket(t, "subfrag.example", 1000)
	subFrag := append([]byte(nil), origPkt...)
	// Set fragment offset = 1 (0x0001) in bytes 6:8
	binary.BigEndian.PutUint16(subFrag[6:8], 0x0001)

	act, off := FastPathInspect(subFrag)
	if act != ActionPassFastPath {
		t.Errorf("FastPathInspect on subsequent fragment: got %s, want ActionPassFastPath", act)
	}
	if off != 0 {
		t.Errorf("FastPathInspect on subsequent fragment: got offset %d, want 0", off)
	}
}

func TestParseFakePacketMode(t *testing.T) {
	testCases := []struct {
		mode        string
		wantEnabled bool
		wantTTL     bool
		wantBadChk  bool
		wantErr     bool
	}{
		{"", false, false, false, false},
		{"none", false, false, false, false},
		{"off", false, false, false, false},
		{"disabled", false, false, false, false},
		{"ttl", true, true, false, false},
		{"TTL", true, true, false, false},
		{"multi-ttl", true, true, false, false},
		{"ttl-auto", true, true, false, false},
		{"wrong-chksum", true, false, true, false},
		{"bad-chksum", true, false, true, false},
		{"wrong-checksum", true, false, true, false},
		{"bad-checksum", true, false, true, false},
		{"both", true, true, true, false},
		{"ttl+wrong-chksum", true, true, true, false},
		{"wrong-chksum+ttl", true, true, true, false},
		{"ttl,wrong-chksum", true, true, true, false},
		{"wrong-chksum,ttl", true, true, true, false},
		{"ttl, wrong-chksum", true, true, true, false},
		{"ttl + wrong-checksum", true, true, true, false},
		{"wrong-checksum, ttl", true, true, true, false},
		{"bad-checksum + ttl", true, true, true, false},
		{"bad-chksum | ttl", true, true, true, false},
		{"ttl+invalid", false, false, false, true},
		{"invalid,ttl", false, false, false, true},
		{"invalid-mode", false, false, false, true},
		{"random-garbage", false, false, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			enabled, useTTL, useBadChk, err := ParseFakePacketMode(tc.mode)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseFakePacketMode(%q) err = %v, wantErr = %v", tc.mode, err, tc.wantErr)
			}
			if enabled != tc.wantEnabled || useTTL != tc.wantTTL || useBadChk != tc.wantBadChk {
				t.Fatalf("ParseFakePacketMode(%q) = (%v, %v, %v), want (%v, %v, %v)",
					tc.mode, enabled, useTTL, useBadChk, tc.wantEnabled, tc.wantTTL, tc.wantBadChk)
			}
		})
	}
}

func TestFakePacketStructureValidClientHello(t *testing.T) {
	origSeq := uint32(1234567)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "target.domain.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.FakeSNI = "decoy.example.org"
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (fake packet, real packet), got %d", len(calls))
	}

	// First emitted packet MUST be the fake packet
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}

	// Verify fake packet payload starts with TLS record header 0x16 0x03 0x01
	payload := fakeParsed.Payload
	if len(payload) < 5 || payload[0] != 0x16 || payload[1] != 0x03 || payload[2] != 0x01 {
		t.Fatalf("fake packet payload does not start with TLS record 0x16 0x03 0x01: %x", payload[:min(5, len(payload))])
	}

	// Verify verifiable by tlsparse.ParseClientHello
	res := tlsparse.ParseClientHello(payload, tlsparse.DefaultLimits())
	if res.Status != tlsparse.StatusParsed {
		t.Fatalf("tlsparse failed to parse fake ClientHello: status=%s, reason=%s", res.Status, res.Reason)
	}
	if !res.Metadata.HasSNI || res.Metadata.SNI != "decoy.example.org" {
		t.Fatalf("fake ClientHello SNI = %q (hasSNI=%v), want %q", res.Metadata.SNI, res.Metadata.HasSNI, "decoy.example.org")
	}

	// Test default SNI when FakeSNI is empty
	mockDefault := &MockPacketSender{}
	cfgDefault := DefaultHarnessConfig()
	cfgDefault.Sender = mockDefault
	cfgDefault.FakePacketMode = "wrong-chksum"
	cfgDefault.FakeSNI = ""
	cfgDefault.SplitOffset = "none"

	hDefault := NewHarness(cfgDefault)
	if err := hDefault.HandlePacket(pkt, &addr, mockDefault); err != nil {
		t.Fatalf("HandlePacket default SNI: %v", err)
	}
	callsDefault := mockDefault.Calls()
	fakeDefParsed, err := packetlab.ParseIPv4TCPPacket(callsDefault[0].Packet)
	if err != nil {
		t.Fatalf("parse fake default SNI packet: %v", err)
	}
	resDef := tlsparse.ParseClientHello(fakeDefParsed.Payload, tlsparse.DefaultLimits())
	if resDef.Status != tlsparse.StatusParsed || resDef.Metadata.SNI != DefaultFakeSNI {
		t.Fatalf("fake default SNI = %q, want %q", resDef.Metadata.SNI, DefaultFakeSNI)
	}
}

func TestFakePacketSeqNumMatchesRealPacketExactly(t *testing.T) {
	origSeq := uint32(0x87654321)
	origAck := uint32(0x12345678)
	pktConfig := packetlab.DefaultPacketConfig()
	pktConfig.DstPort = 443
	pktConfig.SeqNum = origSeq
	pktConfig.AckNum = origAck
	pktConfig.Window = 28960
	pktConfig.Payload = buildTestClientHello("test.target.com")

	pkt, err := packetlab.BuildIPv4TCPPacket(pktConfig)
	if err != nil {
		t.Fatalf("build test packet: %v", err)
	}

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 4
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}

	// Verify SeqNum matches real packet SeqNum exactly
	if fakeParsed.SeqNum != origSeq {
		t.Fatalf("fake packet SeqNum = 0x%08X, want exact match 0x%08X", fakeParsed.SeqNum, origSeq)
	}
	// Verify AckNum and Window match
	if fakeParsed.AckNum != origAck {
		t.Fatalf("fake packet AckNum = 0x%08X, want 0x%08X", fakeParsed.AckNum, origAck)
	}
	if fakeParsed.Window != pktConfig.Window {
		t.Fatalf("fake packet Window = %d, want %d", fakeParsed.Window, pktConfig.Window)
	}
	// Verify 4-tuple match
	if fakeParsed.SrcPort != pktConfig.SrcPort || fakeParsed.DstPort != pktConfig.DstPort {
		t.Fatalf("fake packet port mismatch: src=%d, dst=%d", fakeParsed.SrcPort, fakeParsed.DstPort)
	}
	if !bytes.Equal(fakeParsed.SrcIP, pktConfig.SrcIP[:]) || !bytes.Equal(fakeParsed.DstIP, pktConfig.DstIP[:]) {
		t.Fatalf("fake packet IP mismatch: src=%v, dst=%v", fakeParsed.SrcIP, fakeParsed.DstIP)
	}
}

func TestFakePacketLowTTLChecksum(t *testing.T) {
	origSeq := uint32(5000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "ttl.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 4
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	fakePacket := calls[0].Packet
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(fakePacket)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}

	// Verify TTL is exactly 4
	if fakeParsed.TTL != 4 {
		t.Fatalf("fake packet TTL = %d, want 4", fakeParsed.TTL)
	}

	// Verify IPv4 checksum is valid
	okIP, errIP := packetlab.VerifyIPv4Checksum(fakePacket)
	if !okIP || errIP != nil {
		t.Fatalf("fake packet IPv4 checksum invalid: ok=%v, err=%v", okIP, errIP)
	}

	// Verify TCP checksum is valid (since wrong-chksum was not enabled)
	okTCP, errTCP := packetlab.VerifyTCPChecksum(fakePacket)
	if !okTCP || errTCP != nil {
		t.Fatalf("fake packet TCP checksum should be valid under pure TTL mode: ok=%v, err=%v", okTCP, errTCP)
	}

	// Verify metrics
	injected, ttlCount, badCSCount, sendErr := h.FakeStats()
	if injected != 1 {
		t.Errorf("FakePacketsInjected = %d, want 1", injected)
	}
	if ttlCount != 1 {
		t.Errorf("FakeTTLCount = %d, want 1", ttlCount)
	}
	if badCSCount != 0 {
		t.Errorf("FakeBadChecksumCount = %d, want 0", badCSCount)
	}
	if sendErr != 0 {
		t.Errorf("FakeSendErrors = %d, want 0", sendErr)
	}

	// Test Default TTL when FakeTTL is 0 (unspecified)
	mockDef := &MockPacketSender{}
	cfgDef := DefaultHarnessConfig()
	cfgDef.Sender = mockDef
	cfgDef.FakePacketMode = "ttl"
	cfgDef.FakeTTL = 0 // should default to DefaultFakeTTL (5)
	cfgDef.SplitOffset = "none"

	hDef := NewHarness(cfgDef)
	if err := hDef.HandlePacket(pkt, &addr, mockDef); err != nil {
		t.Fatalf("HandlePacket default TTL: %v", err)
	}
	callsDef := mockDef.Calls()
	fakeDefParsed, err := packetlab.ParseIPv4TCPPacket(callsDef[0].Packet)
	if err != nil {
		t.Fatalf("parse fake default TTL packet: %v", err)
	}
	if fakeDefParsed.TTL != DefaultFakeTTL {
		t.Fatalf("fake packet default TTL = %d, want DefaultFakeTTL (%d)", fakeDefParsed.TTL, DefaultFakeTTL)
	}
}

func TestFakePacketWrongChecksum(t *testing.T) {
	origSeq := uint32(6000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "chksum.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	fakePacket := calls[0].Packet
	fakeAddr := calls[0].Addr

	// 1. Verify TCP checksum is deliberately invalid
	okTCP, errTCP := packetlab.VerifyTCPChecksum(fakePacket)
	if okTCP || errTCP != nil {
		t.Fatalf("fake packet TCP checksum must be invalid: ok=%v, err=%v", okTCP, errTCP)
	}

	// 2. Verify IPv4 checksum is valid
	okIP, errIP := packetlab.VerifyIPv4Checksum(fakePacket)
	if !okIP || errIP != nil {
		t.Fatalf("fake packet IPv4 checksum must remain valid: ok=%v, err=%v", okIP, errIP)
	}

	// 3. NIC Hardware Offload Guarantee: SetIPChecksum(true) and SetTCPChecksum(true)
	if !fakeAddr.IPChecksum() {
		t.Fatal("Hardware offload violation: fake packet Address IPChecksum flag must be true")
	}
	if !fakeAddr.TCPChecksum() {
		t.Fatal("Hardware offload violation: fake packet Address TCPChecksum flag must be true")
	}

	// 4. Verify metrics
	injected, ttlCount, badCSCount, sendErr := h.FakeStats()
	if injected != 1 {
		t.Errorf("FakePacketsInjected = %d, want 1", injected)
	}
	if ttlCount != 0 {
		t.Errorf("FakeTTLCount = %d, want 0", ttlCount)
	}
	if badCSCount != 1 {
		t.Errorf("FakeBadChecksumCount = %d, want 1", badCSCount)
	}
	if sendErr != 0 {
		t.Errorf("FakeSendErrors = %d, want 0", sendErr)
	}
}

func TestFakePacketCombinableTTLAndWrongChecksum(t *testing.T) {
	origSeq := uint32(7000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "both.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "both"
	cfg.FakeTTL = 6
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	fakePacket := calls[0].Packet
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(fakePacket)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}

	// Low-TTL active
	if fakeParsed.TTL != 6 {
		t.Fatalf("fake packet TTL = %d, want 6", fakeParsed.TTL)
	}
	okIP, errIP := packetlab.VerifyIPv4Checksum(fakePacket)
	if !okIP || errIP != nil {
		t.Fatalf("fake packet IPv4 checksum invalid: ok=%v, err=%v", okIP, errIP)
	}

	// Bad TCP Checksum active
	okTCP, errTCP := packetlab.VerifyTCPChecksum(fakePacket)
	if okTCP || errTCP != nil {
		t.Fatalf("fake packet TCP checksum must be invalid: ok=%v, err=%v", okTCP, errTCP)
	}

	// Offload flags
	if !calls[0].Addr.IPChecksum() || !calls[0].Addr.TCPChecksum() {
		t.Fatal("Hardware offload checksum flags must both be true")
	}

	// Combined metrics
	injected, ttlCount, badCSCount, sendErr := h.FakeStats()
	if injected != 1 {
		t.Errorf("FakePacketsInjected = %d, want 1", injected)
	}
	if ttlCount != 1 {
		t.Errorf("FakeTTLCount = %d, want 1", ttlCount)
	}
	if badCSCount != 1 {
		t.Errorf("FakeBadChecksumCount = %d, want 1", badCSCount)
	}
	if sendErr != 0 {
		t.Errorf("FakeSendErrors = %d, want 0", sendErr)
	}
}

func TestSequentialInjectionOrderWithSplitSegments(t *testing.T) {
	origSeq := uint32(8000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "pipeline.target.com", origSeq)
	origParsed, err := packetlab.ParseIPv4TCPPacket(pkt)
	if err != nil {
		t.Fatalf("parse orig: %v", err)
	}

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.SplitOffset = "sni-mid" // Enable out-of-order split

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (Fake Packet, Segment 2, Segment 1), got %d", len(calls))
	}

	// 1. Packet 0: Fake Packet emitted first!
	fakePkt, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}
	resFake := tlsparse.ParseClientHello(fakePkt.Payload, tlsparse.DefaultLimits())
	if resFake.Status != tlsparse.StatusParsed || resFake.Metadata.SNI != DefaultFakeSNI {
		t.Fatalf("first packet must be fake ClientHello with %q, got %q", DefaultFakeSNI, resFake.Metadata.SNI)
	}
	if fakePkt.SeqNum != origSeq {
		t.Fatalf("fake packet SeqNum = %d, want origSeq %d", fakePkt.SeqNum, origSeq)
	}
	badTCP, _ := packetlab.VerifyTCPChecksum(calls[0].Packet)
	if badTCP {
		t.Fatal("fake packet must have corrupted TCP checksum")
	}

	// 2. Packet 1: Segment 2 emitted second! (higher SeqNum)
	seg2Pkt, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse seg2 packet: %v", err)
	}

	// 3. Packet 2: Segment 1 emitted third! (original SeqNum)
	seg1Pkt, err := packetlab.ParseIPv4TCPPacket(calls[2].Packet)
	if err != nil {
		t.Fatalf("parse seg1 packet: %v", err)
	}
	if seg1Pkt.SeqNum != origSeq {
		t.Fatalf("segment 1 SeqNum = %d, want %d", seg1Pkt.SeqNum, origSeq)
	}
	expectedSeg2Seq := origSeq + uint32(len(seg1Pkt.Payload))
	if seg2Pkt.SeqNum != expectedSeg2Seq {
		t.Fatalf("segment 2 SeqNum = %d, want %d", seg2Pkt.SeqNum, expectedSeg2Seq)
	}

	// Reconstruct payload bit-for-bit
	reconstructed := append(seg1Pkt.Payload, seg2Pkt.Payload...)
	if !bytes.Equal(reconstructed, origParsed.Payload) {
		t.Fatal("reconstructed payload does not match original ClientHello byte-for-byte")
	}

	// Verify all addresses had checksum flags set
	for i, c := range calls {
		if !c.Addr.IPChecksum() || !c.Addr.TCPChecksum() {
			t.Fatalf("call %d missing checksum offload flags: IP=%v, TCP=%v", i, c.Addr.IPChecksum(), c.Addr.TCPChecksum())
		}
	}

	// Verify stats
	injected, _, badCSCount, _ := h.FakeStats()
	if injected != 1 || badCSCount != 1 {
		t.Fatalf("FakeStats: injected=%d, badCS=%d", injected, badCSCount)
	}
	handshakes, split, segsInjected, fallbacks, sendErrors := h.ExtendedStats()
	if handshakes != 1 || split != 1 || segsInjected != 2 || fallbacks != 0 || sendErrors != 0 {
		t.Fatalf("ExtendedStats mismatch: hs=%d, split=%d, segs=%d, fallbacks=%d, sendErr=%d",
			handshakes, split, segsInjected, fallbacks, sendErrors)
	}
	_, sent, _, _, _ := h.Stats()
	if sent != 3 {
		t.Fatalf("PacketsSent = %d, want 3", sent)
	}
}

func TestSequentialInjectionOrderWithoutSplit(t *testing.T) {
	origSeq := uint32(9000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "unsplit.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 5
	cfg.SplitOffset = "none" // Splitting disabled

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	// Call 0: Fake Packet
	fakePkt, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}
	if fakePkt.TTL != 5 {
		t.Fatalf("fake packet TTL = %d, want 5", fakePkt.TTL)
	}

	// Call 1: Real Packet unmodified!
	if !bytes.Equal(calls[1].Packet, pkt) {
		t.Fatal("second emitted packet must be identical to original real packet bit-for-bit")
	}

	injected, ttlCount, _, _ := h.FakeStats()
	if injected != 1 || ttlCount != 1 {
		t.Fatalf("FakeStats: injected=%d, ttl=%d", injected, ttlCount)
	}
	_, split, _, _, _ := h.ExtendedStats()
	if split != 0 {
		t.Fatalf("PacketsSplit = %d, want 0", split)
	}
	_, sent, _, _, _ := h.Stats()
	if sent != 2 {
		t.Fatalf("PacketsSent = %d, want 2", sent)
	}
}

func TestFakePacketDelay(t *testing.T) {
	pkt := buildTestIPv4TCPClientHelloPacket(t, "delay.target.com", 10000)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.FakePacketDelay = 25 * time.Millisecond
	cfg.SplitOffset = "none"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	start := time.Now()
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 20*time.Millisecond {
		t.Fatalf("FakePacketDelay not observed: elapsed = %v, want >= 20ms", elapsed)
	}
}

func TestFakePacketSynthesisFailureFallback(t *testing.T) {
	origSeq := uint32(11000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "fallback.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 99 // INVALID TTL (outside range 2-16)

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	// Must NOT fail or panic; must safely fall back to sending real packet unmodified
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed on fallback: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call (fallback pass-through of original packet), got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback packet must match original packet bit-for-bit")
	}

	injected, _, _, _ := h.FakeStats()
	if injected != 0 {
		t.Fatalf("FakePacketsInjected = %d, want 0", injected)
	}
	_, _, _, fallbacks, _ := h.ExtendedStats()
	if fallbacks != 1 {
		t.Fatalf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestFakePacketSendFailureProceedsToRealPacket(t *testing.T) {
	origSeq := uint32(12000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "failfake.target.com", origSeq)

	// Sender fails on call 1 (the fake packet send)
	mock := &MockPacketSender{
		failOnCall: 1,
	}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.SplitOffset = "sni-mid"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	// "If sending the fake packet fails, proceed to send the real packet."
	err := h.HandlePacket(pkt, &addr, mock)
	if err != nil {
		t.Fatalf("HandlePacket should succeed in sending real packet despite fake packet send error, got: %v", err)
	}

	// Attempts: 1 (fake failed), 2 (seg2 succeeded), 3 (seg1 succeeded)
	if mock.TotalAttempts() != 3 {
		t.Fatalf("TotalAttempts = %d, want 3", mock.TotalAttempts())
	}
	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("successful calls = %d, want 2 (seg2 and seg1)", len(calls))
	}

	// Verify FakeSendErrors incremented
	_, _, _, fakeSendErr := h.FakeStats()
	if fakeSendErr != 1 {
		t.Fatalf("FakeSendErrors = %d, want 1", fakeSendErr)
	}
	// Out-of-order segments still injected
	_, split, injected, _, _ := h.ExtendedStats()
	if split != 1 || injected != 2 {
		t.Fatalf("split=%d, injected=%d, want 1 and 2", split, injected)
	}
}

func TestFakePacketSendFailureProceedsToUnmodifiedRealPacket(t *testing.T) {
	origSeq := uint32(13000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "failunmod.target.com", origSeq)

	mock := &MockPacketSender{
		failOnCall: 1, // First send (fake packet) fails
	}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	cfg.SplitOffset = "none" // Splitting disabled

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	err := h.HandlePacket(pkt, &addr, mock)
	if err != nil {
		t.Fatalf("HandlePacket error: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("successful calls = %d, want 1", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("sent real packet does not match original packet")
	}

	_, _, _, fakeSendErr := h.FakeStats()
	if fakeSendErr != 1 {
		t.Fatalf("FakeSendErrors = %d, want 1", fakeSendErr)
	}
}

func TestFakePacketIgnoredForNonTargetTraffic(t *testing.T) {
	// A. Outbound HTTP port 80 -> pass-through, no fake packet
	cfgHTTP := packetlab.DefaultPacketConfig()
	cfgHTTP.DstPort = 80
	cfgHTTP.Payload = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	pktHTTP, _ := packetlab.BuildIPv4TCPPacket(cfgHTTP)

	mockHTTP := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mockHTTP
	cfg.FakePacketMode = "wrong-chksum"
	hHTTP := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)
	if err := hHTTP.HandlePacket(pktHTTP, &addr, mockHTTP); err != nil {
		t.Fatal(err)
	}
	if len(mockHTTP.Calls()) != 1 || !bytes.Equal(mockHTTP.Calls()[0].Packet, pktHTTP) {
		t.Fatal("HTTP traffic must pass through unmodified without fake packet")
	}
	injected, _, _, _ := hHTTP.FakeStats()
	if injected != 0 {
		t.Fatalf("FakePacketsInjected on HTTP = %d, want 0", injected)
	}

	// B. Outbound TCP 443 with non-TLS payload (0x17) -> fast-path, no fake packet
	cfgNonTLS := packetlab.DefaultPacketConfig()
	cfgNonTLS.DstPort = 443
	cfgNonTLS.Payload = []byte{0x17, 0x03, 0x03, 0x00, 0x10}
	pktNonTLS, _ := packetlab.BuildIPv4TCPPacket(cfgNonTLS)

	mockNonTLS := &MockPacketSender{}
	cfgNonTLSMode := DefaultHarnessConfig()
	cfgNonTLSMode.Sender = mockNonTLS
	cfgNonTLSMode.FakePacketMode = "wrong-chksum"
	hNonTLS := NewHarness(cfgNonTLSMode)

	if err := hNonTLS.HandlePacket(pktNonTLS, &addr, mockNonTLS); err != nil {
		t.Fatal(err)
	}
	if len(mockNonTLS.Calls()) != 1 || !bytes.Equal(mockNonTLS.Calls()[0].Packet, pktNonTLS) {
		t.Fatal("non-TLS 443 traffic must pass through fast-path without fake packet")
	}
	injectedNonTLS, _, _, _ := hNonTLS.FakeStats()
	if injectedNonTLS != 0 {
		t.Fatalf("FakePacketsInjected on non-TLS = %d, want 0", injectedNonTLS)
	}

	// C. Target domain matching: configured TargetDomains ["*.allowed.com"]
	// Candidate with SNI "unrelated.org" -> pass-through fallback, no fake packet!
	pktUnrelated := buildTestIPv4TCPClientHelloPacket(t, "unrelated.org", 14000)
	mockTarget := &MockPacketSender{}
	cfgTarget := DefaultHarnessConfig()
	cfgTarget.Sender = mockTarget
	cfgTarget.FakePacketMode = "wrong-chksum"
	cfgTarget.TargetDomains = []string{"*.allowed.com"}
	hTarget := NewHarness(cfgTarget)

	if err := hTarget.HandlePacket(pktUnrelated, &addr, mockTarget); err != nil {
		t.Fatal(err)
	}
	if len(mockTarget.Calls()) != 1 || !bytes.Equal(mockTarget.Calls()[0].Packet, pktUnrelated) {
		t.Fatal("unmatched SNI must pass through fallback without fake packet")
	}
	injectedTarget, _, _, _ := hTarget.FakeStats()
	if injectedTarget != 0 {
		t.Fatalf("FakePacketsInjected on unmatched domain = %d, want 0", injectedTarget)
	}
}

func TestFakePacketWithSplittingFailureRecordsFallback(t *testing.T) {
	origSeq := uint32(15000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "splitfail.target.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "wrong-chksum"
	// Request an impossible numeric split offset (e.g. 50000, well past the ~200B ClientHello)
	cfg.SplitOffset = "50000"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (fake packet, then real packet unmodified on split fallback), got %d", len(calls))
	}

	// First emitted is fake packet
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake: %v", err)
	}
	resFake := tlsparse.ParseClientHello(fakeParsed.Payload, tlsparse.DefaultLimits())
	if resFake.Status != tlsparse.StatusParsed {
		t.Fatalf("fake ClientHello status = %s", resFake.Status)
	}

	// Second emitted is the real packet unmodified
	if !bytes.Equal(calls[1].Packet, pkt) {
		t.Fatal("fallback real packet does not match original packet")
	}

	// Verify stats:
	// 1. Fake packet was injected
	injected, _, badCS, _ := h.FakeStats()
	if injected != 1 || badCS != 1 {
		t.Fatalf("FakeStats mismatch: injected=%d, badCS=%d", injected, badCS)
	}
	// 2. Splitting was attempted and FAILED, so PassThroughFallbacks MUST be incremented!
	_, split, segs, fallbacks, sendErr := h.ExtendedStats()
	if split != 0 || segs != 0 || sendErr != 0 {
		t.Fatalf("ExtendedStats mismatch: split=%d, segs=%d, sendErr=%d", split, segs, sendErr)
	}
	if fallbacks != 1 {
		t.Fatalf("PassThroughFallbacks = %d, want 1 (splitting was configured and failed)", fallbacks)
	}
	_, sent, _, _, _ := h.Stats()
	if sent != 2 {
		t.Fatalf("PacketsSent = %d, want 2", sent)
	}
}

func TestCoordinatedPipelineWithDelays(t *testing.T) {
	origSeq := uint32(16000)
	pkt := buildTestIPv4TCPClientHelloPacket(t, "pipeline-delays.example.org", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.Sender = mock
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 4
	cfg.FakePacketDelay = 15 * time.Millisecond
	cfg.SplitOffset = "sni-mid"
	cfg.InterPacketDelay = 15 * time.Millisecond

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	start := time.Now()
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}
	elapsed := time.Since(start)

	// Both FakePacketDelay (15ms) and InterPacketDelay (15ms) must be observed
	if elapsed < 25*time.Millisecond {
		t.Fatalf("Coordinated pipeline delays not observed: elapsed = %v, want >= 25ms", elapsed)
	}

	calls := mock.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (Fake, Seg 2, Seg 1), got %d", len(calls))
	}

	// 1. Fake Packet first
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake: %v", err)
	}
	if fakeParsed.TTL != 4 {
		t.Fatalf("fake TTL = %d, want 4", fakeParsed.TTL)
	}
	if fakeParsed.SeqNum != origSeq {
		t.Fatalf("fake SeqNum = %d, want %d", fakeParsed.SeqNum, origSeq)
	}

	// 2. Segment 2 second
	seg2Parsed, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse seg2: %v", err)
	}

	// 3. Segment 1 third
	seg1Parsed, err := packetlab.ParseIPv4TCPPacket(calls[2].Packet)
	if err != nil {
		t.Fatalf("parse seg1: %v", err)
	}
	if seg1Parsed.SeqNum != origSeq {
		t.Fatalf("seg1 SeqNum = %d, want %d", seg1Parsed.SeqNum, origSeq)
	}
	if seg2Parsed.SeqNum != origSeq+uint32(len(seg1Parsed.Payload)) {
		t.Fatalf("seg2 SeqNum = %d, want %d", seg2Parsed.SeqNum, origSeq+uint32(len(seg1Parsed.Payload)))
	}

	// Reassembled payload verification
	origParsed, _ := packetlab.ParseIPv4TCPPacket(pkt)
	reassembled := append(seg1Parsed.Payload, seg2Parsed.Payload...)
	if !bytes.Equal(reassembled, origParsed.Payload) {
		t.Fatal("reassembled payload mismatch")
	}

	// Stats verification
	injected, ttlCount, _, _ := h.FakeStats()
	if injected != 1 || ttlCount != 1 {
		t.Fatalf("FakeStats: injected=%d, ttl=%d", injected, ttlCount)
	}
	_, split, segs, fallbacks, sendErr := h.ExtendedStats()
	if split != 1 || segs != 2 || fallbacks != 0 || sendErr != 0 {
		t.Fatalf("ExtendedStats mismatch: split=%d, segs=%d, fallbacks=%d, sendErr=%d", split, segs, fallbacks, sendErr)
	}
	_, sent, _, _, _ := h.Stats()
	if sent != 3 {
		t.Fatalf("PacketsSent = %d, want 3", sent)
	}
}

func buildTestIPv4TCPHTTPRequestPacket(t *testing.T, host string, seq uint32) []byte {
	t.Helper()
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 80
	cfg.SeqNum = seq
	cfg.AckNum = 2000
	cfg.TCPFlags = packetlab.TCPFlagACK | packetlab.TCPFlagPSH
	cfg.Payload = []byte(fmt.Sprintf("GET /index.html HTTP/1.1\r\nHost: %s\r\nUser-Agent: dpibypass-test\r\n\r\n", host))

	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build test IPv4 TCP HTTP packet: %v", err)
	}
	return pkt
}

func TestPort80HTTP_OutOfOrderSplit(t *testing.T) {
	origSeq := uint32(100000)
	host := "updates.discord.com"
	pkt := buildTestIPv4TCPHTTPRequestPacket(t, host, origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.DesyncHTTP = true
	cfg.Sender = mock
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 split segments sent, got %d", len(calls))
	}

	// calls[0] is Segment 2; calls[1] is Segment 1
	seg2, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse segment 2: %v", err)
	}
	seg1, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse segment 1: %v", err)
	}

	if seg1.SeqNum != origSeq {
		t.Errorf("seg1 SeqNum = %d, want original %d", seg1.SeqNum, origSeq)
	}
	expectedSeg2Seq := origSeq + uint32(len(seg1.Payload))
	if seg2.SeqNum != expectedSeg2Seq {
		t.Errorf("seg2 SeqNum = %d, want %d", seg2.SeqNum, expectedSeg2Seq)
	}

	// Address hardware offload checksum flags
	if !calls[0].Addr.IPChecksum() || !calls[0].Addr.TCPChecksum() {
		t.Error("calls[0] missing IP or TCP hardware offload checksum bit")
	}
	if !calls[1].Addr.IPChecksum() || !calls[1].Addr.TCPChecksum() {
		t.Error("calls[1] missing IP or TCP hardware offload checksum bit")
	}

	// Byte-for-byte reassembly verification
	origParsed, _ := packetlab.ParseIPv4TCPPacket(pkt)
	reassembled := append(seg1.Payload, seg2.Payload...)
	if !bytes.Equal(reassembled, origParsed.Payload) {
		t.Fatalf("reassembled payload mismatch:\ngot:  %q\nwant: %q", string(reassembled), string(origParsed.Payload))
	}

	// Stats verification
	_, split, injected, fallbacks, sendErrors := h.ExtendedStats()
	if split != 1 {
		t.Errorf("PacketsSplit = %d, want 1", split)
	}
	if injected != 2 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 2", injected)
	}
	if fallbacks != 0 {
		t.Errorf("PassThroughFallbacks = %d, want 0", fallbacks)
	}
	if sendErrors != 0 {
		t.Errorf("SendErrors = %d, want 0", sendErrors)
	}
}

func TestPort80HTTP_FakePacketAndSplit(t *testing.T) {
	origSeq := uint32(200000)
	host := "www.roblox.com"
	pkt := buildTestIPv4TCPHTTPRequestPacket(t, host, origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.DesyncHTTP = true
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 5
	cfg.FakeSNI = "www.example.com"
	cfg.Sender = mock
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (1 fake + 2 split), got %d", len(calls))
	}

	// 1. First emitted packet: Fake packet
	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}
	if fakeParsed.TTL != 5 {
		t.Errorf("fake packet TTL = %d, want 5", fakeParsed.TTL)
	}
	if fakeParsed.SeqNum != origSeq {
		t.Errorf("fake packet SeqNum = %d, want %d", fakeParsed.SeqNum, origSeq)
	}
	expectedDummy := "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
	if string(fakeParsed.Payload) != expectedDummy {
		t.Errorf("fake packet payload = %q, want %q", string(fakeParsed.Payload), expectedDummy)
	}
	if !calls[0].Addr.IPChecksum() || !calls[0].Addr.TCPChecksum() {
		t.Error("fake packet missing IP/TCP checksum flags on Address")
	}

	// 2. Second emitted packet: Segment 2
	seg2Parsed, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse segment 2: %v", err)
	}

	// 3. Third emitted packet: Segment 1
	seg1Parsed, err := packetlab.ParseIPv4TCPPacket(calls[2].Packet)
	if err != nil {
		t.Fatalf("parse segment 1: %v", err)
	}

	if seg1Parsed.SeqNum != origSeq {
		t.Errorf("seg1 SeqNum = %d, want %d", seg1Parsed.SeqNum, origSeq)
	}
	if seg2Parsed.SeqNum != origSeq+uint32(len(seg1Parsed.Payload)) {
		t.Errorf("seg2 SeqNum = %d, want %d", seg2Parsed.SeqNum, origSeq+uint32(len(seg1Parsed.Payload)))
	}

	// Reassembled payload verification
	origParsed, _ := packetlab.ParseIPv4TCPPacket(pkt)
	reassembled := append(seg1Parsed.Payload, seg2Parsed.Payload...)
	if !bytes.Equal(reassembled, origParsed.Payload) {
		t.Fatalf("reassembled payload mismatch: got %q, want %q", string(reassembled), string(origParsed.Payload))
	}

	// Fake stats
	injected, ttlCount, badChk, _ := h.FakeStats()
	if injected != 1 || ttlCount != 1 || badChk != 0 {
		t.Errorf("FakeStats: injected=%d, ttl=%d, badChk=%d", injected, ttlCount, badChk)
	}
}

type mockRuleMatcher struct {
	rules map[string]string
}

func (m *mockRuleMatcher) Match(domain string) (string, bool) {
	if prof, ok := m.rules[domain]; ok {
		return prof, true
	}
	return "", false
}

func TestPort80HTTP_DomainMatcherNone(t *testing.T) {
	origSeq := uint32(300000)
	pkt := buildTestIPv4TCPHTTPRequestPacket(t, "allowed.example.com", origSeq)

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.DesyncHTTP = true
	cfg.DomainMatcher = &mockRuleMatcher{
		rules: map[string]string{
			"allowed.example.com": "none",
		},
	}
	cfg.Sender = mock
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 pass-through call for 'none' profile, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("pass-through packet content mismatch")
	}

	_, split, _, fallbacks, _ := h.ExtendedStats()
	if split != 0 || fallbacks != 1 {
		t.Errorf("split=%d, fallbacks=%d; want 0, 1", split, fallbacks)
	}
}

func TestPort80HTTP_NoHostHeader_PassThrough(t *testing.T) {
	cfgPkt := packetlab.DefaultPacketConfig()
	cfgPkt.DstPort = 80
	cfgPkt.Payload = []byte("GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
	pkt, err := packetlab.BuildIPv4TCPPacket(cfgPkt)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	mock := &MockPacketSender{}
	cfg := DefaultHarnessConfig()
	cfg.DesyncHTTP = true
	cfg.Sender = mock
	h := NewHarness(cfg)

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 pass-through call when no Host header, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("fallback packet mismatch")
	}

	_, split, _, fallbacks, _ := h.ExtendedStats()
	if split != 0 {
		t.Errorf("PacketsSplit = %d, want 0", split)
	}
	if fallbacks != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
	}
}

func TestHarnessPauseResumeAntiCheat(t *testing.T) {
	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)

	if h.IsPaused() {
		t.Fatal("harness should not start paused")
	}

	// Calling Pause
	if err := h.Pause(); err != nil {
		t.Fatalf("Pause failed: %v", err)
	}
	if !h.IsPaused() {
		t.Fatal("harness should be paused after Pause()")
	}

	// Idempotent Pause
	if err := h.Pause(); err != nil {
		t.Fatalf("idempotent Pause failed: %v", err)
	}
	if !h.IsPaused() {
		t.Fatal("harness should still be paused")
	}

	// Resume without elevated driver handles:
	// In offline test, Resume attempts startLocked which fails because offline test is not elevated / no DLL,
	// or returns error on stub. On stub, Resume returns nil.
	_ = h.Resume()
}

func TestHTTPWireDesync_Port80_FakePacketAndOutOfOrderSplitAndReassembly(t *testing.T) {
	httpPayload := []byte("GET /test/path HTTP/1.1\r\nHost: updates.discord.com\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n")
	origSeq := uint32(100000)

	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 80
	pktCfg.SeqNum = origSeq
	pktCfg.Payload = httpPayload
	pktCfg.TCPFlags = packetlab.TCPFlagACK | packetlab.TCPFlagPSH

	pkt, err := packetlab.BuildIPv4TCPPacket(pktCfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.DesyncHTTP = true
	hCfg.FakePacketMode = "ttl"
	hCfg.FakeTTL = 5
	hCfg.FakeSNI = "www.example.com"
	hCfg.SplitOffset = "sni-mid"
	hCfg.TargetDomains = []string{"updates.discord.com"}
	hCfg.DefaultProfile = "packet"

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 packet emissions (1 fake + 2 split segments), got %d", len(calls))
	}

	// 1. First emission: Synthetic Fake Packet
	fakeCall := calls[0]
	fakePkt := fakeCall.Packet
	if !fakeCall.Addr.IPChecksum() || !fakeCall.Addr.TCPChecksum() {
		t.Errorf("fake packet must request hardware checksum offload (SetIPChecksum and SetTCPChecksum)")
	}
	parsedFake, err := packetlab.ParseIPv4TCPPacket(fakePkt)
	if err != nil {
		t.Fatalf("failed parsing fake packet: %v", err)
	}
	if parsedFake.TTL != 5 {
		t.Errorf("fake packet TTL = %d, want 5", parsedFake.TTL)
	}
	if parsedFake.DstPort != 80 {
		t.Errorf("fake packet DstPort = %d, want 80", parsedFake.DstPort)
	}
	expectedDummy := packetlab.BuildDummyHTTPRequest("www.example.com")
	if !bytes.Equal(parsedFake.Payload, expectedDummy) {
		t.Errorf("fake packet payload = %q, want %q", string(parsedFake.Payload), string(expectedDummy))
	}

	// 2. Second emission: Real Segment 2 (Out-of-Order emission)
	seg2Call := calls[1]
	parsedSeg2, err := packetlab.ParseIPv4TCPPacket(seg2Call.Packet)
	if err != nil {
		t.Fatalf("failed parsing segment 2: %v", err)
	}
	if parsedSeg2.DstPort != 80 {
		t.Errorf("segment 2 DstPort = %d, want 80", parsedSeg2.DstPort)
	}
	if parsedSeg2.SeqNum <= origSeq {
		t.Errorf("segment 2 SeqNum = %d, want > %d", parsedSeg2.SeqNum, origSeq)
	}
	if parsedSeg2.TCPFlags&packetlab.TCPFlagPSH == 0 {
		t.Errorf("segment 2 must preserve original PSH flag")
	}

	// 3. Third emission: Real Segment 1 (Emitted after Segment 2)
	seg1Call := calls[2]
	parsedSeg1, err := packetlab.ParseIPv4TCPPacket(seg1Call.Packet)
	if err != nil {
		t.Fatalf("failed parsing segment 1: %v", err)
	}
	if parsedSeg1.DstPort != 80 {
		t.Errorf("segment 1 DstPort = %d, want 80", parsedSeg1.DstPort)
	}
	if parsedSeg1.SeqNum != origSeq {
		t.Errorf("segment 1 SeqNum = %d, want %d", parsedSeg1.SeqNum, origSeq)
	}
	if parsedSeg1.TCPFlags&packetlab.TCPFlagPSH != 0 {
		t.Errorf("segment 1 must clear PSH flag")
	}

	// 4. Byte-for-byte reassembly verification
	reassembled := append([]byte(nil), parsedSeg1.Payload...)
	reassembled = append(reassembled, parsedSeg2.Payload...)
	if !bytes.Equal(reassembled, httpPayload) {
		t.Fatalf("reassembled payload does not match original HTTP payload!\nReassembled: %q\nOriginal:    %q", string(reassembled), string(httpPayload))
	}

	// 5. Split boundary verification: split must be inside "Host: updates.discord.com"
	_, valStart, valEnd, found := packetlab.FindHTTPHost(httpPayload)
	if !found {
		t.Fatal("FindHTTPHost failed on test payload")
	}
	splitOffset := len(parsedSeg1.Payload)
	if splitOffset <= valStart || splitOffset >= valEnd {
		t.Errorf("split offset %d is not within Host header bounds [%d, %d)", splitOffset, valStart, valEnd)
	}

	// 6. Metrics verification
	recv, sent, _, fp, cand := h.Stats()
	handshakes, split, ooo, fb, errs := h.ExtendedStats()
	fakeInj, fakeTTL, _, _ := h.FakeStats()

	if recv != 1 {
		t.Errorf("PacketsRecv = %d, want 1", recv)
	}
	if sent != 3 {
		t.Errorf("PacketsSent = %d, want 3", sent)
	}
	if fp != 0 {
		t.Errorf("TCPFastPath = %d, want 0", fp)
	}
	if cand != 1 {
		t.Errorf("TCPCandidate = %d, want 1", cand)
	}
	if handshakes != 1 {
		t.Errorf("CandidateHandshakes = %d, want 1", handshakes)
	}
	if split != 1 {
		t.Errorf("PacketsSplit = %d, want 1", split)
	}
	if ooo != 2 {
		t.Errorf("OutOfOrderSegmentsInjected = %d, want 2", ooo)
	}
	if fb != 0 {
		t.Errorf("PassThroughFallbacks = %d, want 0", fb)
	}
	if errs != 0 {
		t.Errorf("SendErrors = %d, want 0", errs)
	}
	if fakeInj != 1 {
		t.Errorf("FakePacketsInjected = %d, want 1", fakeInj)
	}
	if fakeTTL != 1 {
		t.Errorf("FakeTTLCount = %d, want 1", fakeTTL)
	}
}

func TestHTTPWireDesync_Port80_DesyncDisabled(t *testing.T) {
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: updates.discord.com\r\n\r\n")
	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 80
	pktCfg.Payload = httpPayload
	pkt, _ := packetlab.BuildIPv4TCPPacket(pktCfg)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.DesyncHTTP = false
	hCfg.FakePacketMode = "ttl"
	hCfg.TargetDomains = []string{"updates.discord.com"}

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 unmodified pass-through packet, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("packet was modified when DesyncHTTP was false")
	}

	fakeInj, _, _, _ := h.FakeStats()
	if fakeInj != 0 {
		t.Errorf("fake packets injected = %d, want 0", fakeInj)
	}
}

func TestHTTPWireDesync_Port80_DomainRuleNone(t *testing.T) {
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: excluded.domain.com\r\n\r\n")
	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 80
	pktCfg.Payload = httpPayload
	pkt, _ := packetlab.BuildIPv4TCPPacket(pktCfg)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.DesyncHTTP = true
	hCfg.FakePacketMode = "ttl"
	hCfg.TargetDomains = []string{"updates.discord.com"}
	hCfg.DefaultProfile = "none"

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 unmodified pass-through packet, got %d", len(calls))
	}
	if !bytes.Equal(calls[0].Packet, pkt) {
		t.Fatal("packet was modified for excluded domain")
	}
}

func TestHTTPWireDesync_Port80_NoHostHeaderFallback(t *testing.T) {
	httpPayload := []byte("GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n")
	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 80
	pktCfg.Payload = httpPayload
	pkt, _ := packetlab.BuildIPv4TCPPacket(pktCfg)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.DesyncHTTP = true
	hCfg.FakePacketMode = "ttl"

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 pass-through fallback packet, got %d", len(calls))
	}

	_, _, _, fb, _ := h.ExtendedStats()
	if fb != 1 {
		t.Errorf("PassThroughFallbacks = %d, want 1", fb)
	}
}

func TestHTTPWireDesync_Port80_ProcessPacket(t *testing.T) {
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: updates.discord.com\r\n\r\n")
	pktCfg := packetlab.DefaultPacketConfig()
	pktCfg.DstPort = 80
	pktCfg.Payload = httpPayload
	pkt, _ := packetlab.BuildIPv4TCPPacket(pktCfg)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.DesyncHTTP = true
	hCfg.FakePacketMode = "ttl"
	hCfg.TargetDomains = []string{"updates.discord.com"}

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	action, _, err := h.ProcessPacket(pkt, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if action != ActionInspectCandidate {
		t.Errorf("action = %v, want ActionInspectCandidate", action)
	}
	if len(sender.Calls()) != 3 {
		t.Errorf("ProcessPacket emissions = %d, want 3", len(sender.Calls()))
	}
}

type mockDNSResolver struct {
	resolveFn func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error)
}

func (m *mockDNSResolver) ResolveQueryType(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
	if m.resolveFn != nil {
		return m.resolveFn(ctx, domain, qtype)
	}
	return nil, 0, false, errors.New("mock resolver not implemented")
}

func buildTestUDP53QueryPacket(srcIP, dstIP [4]byte, srcPort uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 17 // UDP
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

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], 53)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)

	return pkt
}

func TestDNSInterception_Success_A(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(53123)

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeA, 0x7777)
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	resolvedIPs := []net.IP{net.ParseIP("162.159.130.233"), net.ParseIP("162.159.133.233")}
	mockRes := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			if domain == "updates.discord.com" && qtype == dnsdoh.TypeA {
				return resolvedIPs, 180 * time.Second, false, nil
			}
			return nil, 0, false, errors.New("unexpected query")
		},
	}

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = mockRes

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(queryPkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	// Wait up to 500ms for async worker completion
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(sender.Calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 injected packet, got %d", len(calls))
	}

	sentCall := calls[0]
	// Verify WinDivert Address flags: Outbound=false, IPChecksum=true, UDPChecksum=true
	if sentCall.Addr.Outbound() {
		t.Error("expected Outbound=false for synthesized inbound DNS response")
	}
	if !sentCall.Addr.IPChecksum() {
		t.Error("expected IPChecksum=true")
	}
	if !sentCall.Addr.UDPChecksum() {
		t.Error("expected UDPChecksum=true")
	}

	// Verify swapped 4-tuple
	respPkt := sentCall.Packet
	respSrcIP := net.IP(respPkt[12:16])
	respDstIP := net.IP(respPkt[16:20])
	respSrcPort := binary.BigEndian.Uint16(respPkt[20:22])
	respDstPort := binary.BigEndian.Uint16(respPkt[22:24])

	if !respSrcIP.Equal(net.IP(dnsServerIP[:])) {
		t.Errorf("SrcIP = %v, want %v", respSrcIP, dnsServerIP)
	}
	if !respDstIP.Equal(net.IP(clientIP[:])) {
		t.Errorf("DstIP = %v, want %v", respDstIP, clientIP)
	}
	if respSrcPort != 53 {
		t.Errorf("SrcPort = %d, want 53", respSrcPort)
	}
	if respDstPort != clientPort {
		t.Errorf("DstPort = %d, want %d", respDstPort, clientPort)
	}

	// Verify checksums
	if ok, err := packetlab.VerifyIPv4Checksum(respPkt); !ok || err != nil {
		t.Errorf("IPv4 checksum invalid: %v, err=%v", ok, err)
	}
	if ok, err := packetlab.VerifyUDPChecksum(respPkt); !ok || err != nil {
		t.Errorf("UDP checksum invalid: %v, err=%v", ok, err)
	}

	// Parse synthesized DNS response
	dnsWire := respPkt[28:]
	parsed, err := dnsdoh.ParseResponse(dnsWire, 0x7777, "updates.discord.com", dnsdoh.TypeA)
	if err != nil {
		t.Fatalf("ParseResponse on synthesized packet: %v", err)
	}
	if len(parsed.IPs) != 2 || !parsed.IPs[0].Equal(resolvedIPs[0]) {
		t.Errorf("resolved IPs mismatch: got %v, want %v", parsed.IPs, resolvedIPs)
	}

	// Verify stats
	intercepted, dohResolved, fallbacks := h.DNSStats()
	if intercepted != 1 || dohResolved != 1 || fallbacks != 0 {
		t.Errorf("DNSStats: got (%d, %d, %d), want (1, 1, 0)", intercepted, dohResolved, fallbacks)
	}
}

func TestDNSInterception_Success_AAAA_NODATA(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(53124)

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeAAAA, 0x8888)
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	mockRes := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			return nil, 60 * time.Second, true, nil // NODATA
		},
	}

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = mockRes

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(queryPkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for len(sender.Calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 injected packet, got %d", len(calls))
	}

	respPkt := calls[0].Packet
	if calls[0].Addr.Outbound() {
		t.Error("expected Outbound=false")
	}

	// Verify NODATA
	dnsWire := respPkt[28:]
	_, err = dnsdoh.ParseResponse(dnsWire, 0x8888, "updates.discord.com", dnsdoh.TypeAAAA)
	if !errors.Is(err, dnsdoh.ErrNoData) {
		t.Errorf("expected ErrNoData, got %v", err)
	}

	intercepted, dohResolved, fallbacks := h.DNSStats()
	if intercepted != 1 || dohResolved != 1 || fallbacks != 0 {
		t.Errorf("DNSStats: got (%d, %d, %d), want (1, 1, 0)", intercepted, dohResolved, fallbacks)
	}
}

func TestDNSInterception_Fallback_NonTargetQType(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(53125)

	// QTYPE TXT = 16
	queryWire, err := dnsdoh.BuildQuery("example.com", 16, 0x9999)
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = &mockDNSResolver{}

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(queryPkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback emission, got %d", len(calls))
	}

	// Inbound SERVFAIL response must be synthesized (no outbound re-injection loop)
	if calls[0].Addr.Outbound() {
		t.Error("expected Outbound=false for synthesized inbound SERVFAIL response")
	}
	respPayload := calls[0].Packet[28:]
	_, parseErr := dnsdoh.ParseResponse(respPayload, 0x9999, "example.com", 16)
	if !errors.Is(parseErr, dnsdoh.ErrServFail) {
		t.Errorf("expected ErrServFail, got %v", parseErr)
	}

	intercepted, dohResolved, fallbacks := h.DNSStats()
	if intercepted != 1 || dohResolved != 0 || fallbacks != 1 {
		t.Errorf("DNSStats: got (%d, %d, %d), want (1, 0, 1)", intercepted, dohResolved, fallbacks)
	}
}

func TestDNSInterception_PTR_NODATA(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{8, 8, 8, 8}
	clientPort := uint16(53127)

	// Reverse PTR query for server IP (e.g. from nslookup)
	queryWire, err := dnsdoh.BuildQuery("8.8.8.8.in-addr.arpa", dnsdoh.TypePTR, 0x5555)
	if err != nil {
		t.Fatalf("BuildQuery PTR: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = &mockDNSResolver{}

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(queryPkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket PTR: %v", err)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 synthesized NODATA emission, got %d", len(calls))
	}

	respAddr := calls[0].Addr
	if respAddr.Outbound() {
		t.Error("expected Outbound=false for synthesized inbound DNS response")
	}

	// Verify synthesized DNS response header
	respPkt := calls[0].Packet
	if len(respPkt) < 28+12 {
		t.Fatalf("synthesized packet too short: %d", len(respPkt))
	}
	dnsWire := respPkt[28:]
	id := binary.BigEndian.Uint16(dnsWire[0:2])
	if id != 0x5555 {
		t.Errorf("ID = 0x%04X, want 0x5555", id)
	}
	flags := binary.BigEndian.Uint16(dnsWire[2:4])
	if flags&0x8000 == 0 {
		t.Error("expected QR=1 (response)")
	}
	anCount := binary.BigEndian.Uint16(dnsWire[6:8])
	if anCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 (clean NODATA)", anCount)
	}

	intercepted, dohResolved, fallbacks := h.DNSStats()
	if intercepted != 1 || dohResolved != 1 || fallbacks != 0 {
		t.Errorf("DNSStats: got (%d, %d, %d), want (1, 1, 0)", intercepted, dohResolved, fallbacks)
	}
}

func TestDNSInterception_Fallback_DoHError(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(53126)

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeA, 0xAAAA)
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	mockRes := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			return nil, 0, false, errors.New("all DoH endpoints unreachable")
		},
	}

	sender := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = sender
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = mockRes

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(queryPkt, &addr, sender); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	// Wait up to 500ms for async worker completion
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(sender.Calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 fallback emission, got %d", len(calls))
	}

	// Inbound SERVFAIL response must be synthesized (no outbound re-injection loop)
	if calls[0].Addr.Outbound() {
		t.Error("expected Outbound=false for synthesized inbound SERVFAIL response")
	}
	respPayload := calls[0].Packet[28:]
	_, parseErr := dnsdoh.ParseResponse(respPayload, 0xAAAA, "updates.discord.com", dnsdoh.TypeA)
	if !errors.Is(parseErr, dnsdoh.ErrServFail) {
		t.Errorf("expected ErrServFail, got %v", parseErr)
	}

	intercepted, dohResolved, fallbacks := h.DNSStats()
	if intercepted != 1 || dohResolved != 0 || fallbacks != 1 {
		t.Errorf("DNSStats: got (%d, %d, %d), want (1, 0, 1)", intercepted, dohResolved, fallbacks)
	}
}

func TestDNSInterception_ProcessPacket(t *testing.T) {
	clientIP := [4]byte{192, 168, 1, 105}
	dnsServerIP := [4]byte{195, 175, 254, 2}
	clientPort := uint16(53127)

	queryWire, err := dnsdoh.BuildQuery("www.roblox.com", dnsdoh.TypeA, 0xBBBB)
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	queryPkt := buildTestUDP53QueryPacket(clientIP, dnsServerIP, clientPort, queryWire)

	mockRes := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			return []net.IP{net.ParseIP("128.116.119.3")}, 300 * time.Second, false, nil
		},
	}

	hCfg := DefaultHarnessConfig()
	hCfg.InterceptDNS = true
	hCfg.DNSResolver = mockRes

	h := NewHarness(hCfg)
	var addr Address
	addr.SetOutbound(true)

	action, respPkt, err := h.ProcessPacket(queryPkt, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if action != ActionInterceptDNS {
		t.Errorf("action = %v, want ActionInterceptDNS", action)
	}
	if respPkt == nil {
		t.Fatal("expected synthesized response packet")
	}
	if addr.Outbound() {
		t.Error("expected ProcessPacket to update addr: Outbound must be false")
	}
	if !addr.IPChecksum() || !addr.UDPChecksum() {
		t.Error("expected ProcessPacket to set IPChecksum and UDPChecksum on addr")
	}

	// Verify IPv4 and UDP checksums
	if ok, err := packetlab.VerifyIPv4Checksum(respPkt); !ok || err != nil {
		t.Errorf("IPv4 checksum invalid: %v, err=%v", ok, err)
	}
	if ok, err := packetlab.VerifyUDPChecksum(respPkt); !ok || err != nil {
		t.Errorf("UDP checksum invalid: %v, err=%v", ok, err)
	}

	dnsWire := respPkt[28:]
	parsed, err := dnsdoh.ParseResponse(dnsWire, 0xBBBB, "www.roblox.com", dnsdoh.TypeA)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(parsed.IPs) != 1 || !parsed.IPs[0].Equal(net.ParseIP("128.116.119.3")) {
		t.Errorf("parsed IPs mismatch: %v", parsed.IPs)
	}
}

func TestHarness_DoHEndpointSelfExclusion(t *testing.T) {
	dohDomains := []string{
		"cloudflare-dns.com",
		"dns.google",
		"one.one.one.one",
		"custom-doh.example.net",
		"sub.cloudflare-dns.com",
	}

	for _, domain := range dohDomains {
		t.Run(domain, func(t *testing.T) {
			pkt := buildTestIPv4TCPClientHelloPacket(t, domain, 10000)

			mock := &MockPacketSender{}
			cfg := DefaultHarnessConfig()
			cfg.Sender = mock
			cfg.FakePacketMode = "ttl"
			cfg.FakeTTL = 4
			cfg.SplitOffset = "sni-mid"
			cfg.DefaultProfile = "packet"
			// Pass as full URL with path to verify URL normalization
			cfg.DoHEndpoints = []string{"https://custom-doh.example.net/dns-query"}

			h := NewHarness(cfg)
			var addr Address
			addr.SetOutbound(true)

			if err := h.HandlePacket(pkt, &addr, mock); err != nil {
				t.Fatalf("HandlePacket failed: %v", err)
			}

			calls := mock.Calls()
			if len(calls) != 1 {
				t.Fatalf("expected 1 pass-through emission for DoH domain %q, got %d", domain, len(calls))
			}
			if !bytes.Equal(calls[0].Packet, pkt) {
				t.Fatalf("packet modified for DoH domain %q", domain)
			}

			injected, _, _, _ := h.FakeStats()
			if injected != 0 {
				t.Errorf("FakePacketsInjected = %d, want 0", injected)
			}
			_, split, _, fallbacks, _ := h.ExtendedStats()
			if split != 0 {
				t.Errorf("PacketsSplit = %d, want 0", split)
			}
			if fallbacks != 1 {
				t.Errorf("PassThroughFallbacks = %d, want 1", fallbacks)
			}
		})
	}

	t.Run("NonExcludedTargetIsSplittedAndFaked", func(t *testing.T) {
		pkt := buildTestIPv4TCPClientHelloPacket(t, "updates.discord.com", 20000)

		mock := &MockPacketSender{}
		cfg := DefaultHarnessConfig()
		cfg.Sender = mock
		cfg.FakePacketMode = "ttl"
		cfg.FakeTTL = 4
		cfg.SplitOffset = "sni-mid"
		cfg.DefaultProfile = "packet"
		cfg.DoHEndpoints = []string{"custom-doh.example.net"}

		h := NewHarness(cfg)
		var addr Address
		addr.SetOutbound(true)

		if err := h.HandlePacket(pkt, &addr, mock); err != nil {
			t.Fatalf("HandlePacket failed: %v", err)
		}

		calls := mock.Calls()
		if len(calls) != 3 {
			t.Fatalf("expected 3 emissions (1 fake + 2 split) for non-excluded domain, got %d", len(calls))
		}
		injected, _, _, _ := h.FakeStats()
		if injected != 1 {
			t.Errorf("FakePacketsInjected = %d, want 1", injected)
		}
		_, split, _, _, _ := h.ExtendedStats()
		if split != 1 {
			t.Errorf("PacketsSplit = %d, want 1", split)
		}
	})
}

func TestHarness_RetransmissionEscalationLadder(t *testing.T) {
	tempDir := t.TempDir()
	persistFile := filepath.Join(tempDir, "autolearn.json")
	al := NewAutoLearner(persistFile, true)

	var nowMu sync.Mutex
	currTime := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return currTime
	})

	cfg := DefaultHarnessConfig()
	cfg.AutoLearner = al
	cfg.AutoLearn = true
	cfg.DefaultProfile = "packet"
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 5
	cfg.SplitOffset = "sni-mid"

	h := NewHarness(cfg)
	var addr Address
	addr.SetOutbound(true)

	domain := "escalate.target.com"
	pkt := buildTestIPv4TCPClientHelloPacket(t, domain, 30000)

	// Attempt 0: Initial transmission -> Stage 0 (default TTL 5, split sni-mid)
	mock0 := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock0); err != nil {
		t.Fatalf("HandlePacket attempt 0: %v", err)
	}
	calls0 := mock0.Calls()
	if len(calls0) != 3 {
		t.Fatalf("attempt 0: expected 3 packets (fake + 2 segments), got %d", len(calls0))
	}
	fakeParsed0, err := packetlab.ParseIPv4TCPPacket(calls0[0].Packet)
	if err != nil {
		t.Fatalf("parse fake 0: %v", err)
	}
	if fakeParsed0.TTL != 5 {
		t.Errorf("attempt 0 fake TTL = %d, want 5", fakeParsed0.TTL)
	}
	retrans, esc, _ := h.AutoLearnStats()
	if retrans != 0 || esc != 0 {
		t.Errorf("stats after attempt 0: retrans=%d, esc=%d, want 0, 0", retrans, esc)
	}

	// Attempt 1: Retransmission at +500ms -> Stage 1 (TTL 2, split sni-start)
	nowMu.Lock()
	currTime = currTime.Add(500 * time.Millisecond)
	nowMu.Unlock()

	mock1 := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock1); err != nil {
		t.Fatalf("HandlePacket retry 1: %v", err)
	}
	calls1 := mock1.Calls()
	if len(calls1) != 3 {
		t.Fatalf("retry 1: expected 3 packets (fake + 2 segments), got %d", len(calls1))
	}
	fakeParsed1, err := packetlab.ParseIPv4TCPPacket(calls1[0].Packet)
	if err != nil {
		t.Fatalf("parse fake 1: %v", err)
	}
	if fakeParsed1.TTL != 3 {
		t.Errorf("retry 1 fake TTL = %d, want 3 (Stage 1)", fakeParsed1.TTL)
	}
	retrans, esc, _ = h.AutoLearnStats()
	if retrans != 1 || esc != 1 {
		t.Errorf("stats after retry 1: retrans=%d, esc=%d, want 1, 1", retrans, esc)
	}

	// Verify segment split offset is sni-mid (seg2 emitted first, seg1 emitted second)
	seg1Parsed1, err := packetlab.ParseIPv4TCPPacket(calls1[2].Packet)
	if err != nil {
		t.Fatalf("parse seg1 retry 1: %v", err)
	}
	seg1Parsed0, err := packetlab.ParseIPv4TCPPacket(calls0[2].Packet)
	if err != nil {
		t.Fatalf("parse seg1 attempt 0: %v", err)
	}
	if len(seg1Parsed1.Payload) != len(seg1Parsed0.Payload) {
		t.Errorf("sni-mid seg1 payload length (%d) should match attempt 0 (%d)",
			len(seg1Parsed1.Payload), len(seg1Parsed0.Payload))
	}

	// Attempt 2: Retransmission at +1000ms -> Stage 2 (TTL 5, split sni-end, 2ms delay)
	nowMu.Lock()
	currTime = currTime.Add(500 * time.Millisecond)
	nowMu.Unlock()

	mock2 := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock2); err != nil {
		t.Fatalf("HandlePacket retry 2: %v", err)
	}
	calls2 := mock2.Calls()
	if len(calls2) != 3 {
		t.Fatalf("retry 2: expected 3 packets, got %d", len(calls2))
	}
	fakeParsed2, err := packetlab.ParseIPv4TCPPacket(calls2[0].Packet)
	if err != nil {
		t.Fatalf("parse fake 2: %v", err)
	}
	if fakeParsed2.TTL != 5 {
		t.Errorf("retry 2 fake TTL = %d, want 5 (Stage 2)", fakeParsed2.TTL)
	}
	retrans, esc, _ = h.AutoLearnStats()
	if retrans != 2 || esc != 2 {
		t.Errorf("stats after retry 2: retrans=%d, esc=%d, want 2, 2", retrans, esc)
	}

	// Attempt 3: Retransmission at +1500ms -> Stage 3 (pure OOO split sni-mid, fake_mode=none)
	nowMu.Lock()
	currTime = currTime.Add(500 * time.Millisecond)
	nowMu.Unlock()

	mock3 := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock3); err != nil {
		t.Fatalf("HandlePacket retry 3: %v", err)
	}
	calls3 := mock3.Calls()
	if len(calls3) != 2 {
		t.Fatalf("retry 3: expected exactly 2 packets (pure split, no fake), got %d", len(calls3))
	}
	retrans, esc, _ = h.AutoLearnStats()
	if retrans != 3 || esc != 3 {
		t.Errorf("stats after retry 3: retrans=%d, esc=%d, want 3, 3", retrans, esc)
	}
}

func TestHarness_LearnedDomainPersistence(t *testing.T) {
	tempDir := t.TempDir()
	persistFile := filepath.Join(tempDir, "autolearn.json")

	// Phase A: Learn domain at Stage 2 using first harness
	al1 := NewAutoLearner(persistFile, true)
	var nowMu sync.Mutex
	currTime := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	al1.SetNowFunc(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return currTime
	})

	cfg1 := DefaultHarnessConfig()
	cfg1.AutoLearner = al1
	cfg1.AutoLearn = true
	cfg1.DefaultProfile = "packet"
	cfg1.FakePacketMode = "ttl"
	cfg1.FakeTTL = 5
	cfg1.SplitOffset = "sni-mid"

	h1 := NewHarness(cfg1)
	var addr Address
	addr.SetOutbound(true)

	domain := "persisted.target.com"
	pkt1 := buildTestIPv4TCPClientHelloPacket(t, domain, 40000)

	// Attempt 0
	mockA0 := &MockPacketSender{}
	_ = h1.HandlePacket(pkt1, &addr, mockA0)

	// Retry 1 (Stage 1)
	nowMu.Lock()
	currTime = currTime.Add(500 * time.Millisecond)
	nowMu.Unlock()
	mockA1 := &MockPacketSender{}
	_ = h1.HandlePacket(pkt1, &addr, mockA1)

	// Retry 2 (Stage 2)
	nowMu.Lock()
	currTime = currTime.Add(500 * time.Millisecond)
	nowMu.Unlock()
	mockA2 := &MockPacketSender{}
	_ = h1.HandlePacket(pkt1, &addr, mockA2)

	learned := al1.ListLearnedDomains()
	if len(learned) == 0 || learned[0].Stage != 2 {
		t.Fatalf("expected domain to be learned at Stage 2, got: %+v", learned)
	}

	// Phase B: Start fresh harness h2 with new AutoLearner loading from the same JSON file
	al2 := NewAutoLearner(persistFile, true)
	if al2.DomainCount() != 1 {
		t.Fatalf("al2 DomainCount = %d, want 1 loaded from disk", al2.DomainCount())
	}

	cfg2 := DefaultHarnessConfig()
	cfg2.AutoLearner = al2
	cfg2.AutoLearn = true
	cfg2.DefaultProfile = "packet"
	cfg2.FakePacketMode = "ttl"
	cfg2.FakeTTL = 5
	cfg2.SplitOffset = "sni-mid"

	h2 := NewHarness(cfg2)

	// Send a BRAND NEW connection (different sequence number) for the learned domain
	freshPkt := buildTestIPv4TCPClientHelloPacket(t, domain, 80000)
	mockB := &MockPacketSender{}

	if err := h2.HandlePacket(freshPkt, &addr, mockB); err != nil {
		t.Fatalf("h2 HandlePacket fresh connection: %v", err)
	}

	callsB := mockB.Calls()
	if len(callsB) != 3 {
		t.Fatalf("expected 3 packets from h2 (1 fake + 2 split), got %d", len(callsB))
	}

	fakeParsedB, err := packetlab.ParseIPv4TCPPacket(callsB[0].Packet)
	if err != nil {
		t.Fatalf("parse h2 fake packet: %v", err)
	}

	// Must IMMEDIATELY use Stage 2 parameters: TTL = 5!
	if fakeParsedB.TTL != 5 {
		t.Fatalf("h2 fake packet TTL = %d, want 5 (Stage 2 applied immediately on first attempt)", fakeParsedB.TTL)
	}

	// Must not have triggered a retransmission escalation
	retransB, escB, domsB := h2.AutoLearnStats()
	if retransB != 0 || escB != 0 {
		t.Errorf("fresh connection should not detect retransmission: retrans=%d, esc=%d", retransB, escB)
	}
	if domsB != 1 {
		t.Errorf("DomainsAutoLearned = %d, want 1", domsB)
	}
}

func TestHarness_MultiTTL(t *testing.T) {
	if !IsMultiTTL("multi-ttl") || !IsMultiTTL("ttl-auto") || !IsMultiTTL("multi-ttl+wrong-chksum") {
		t.Fatalf("IsMultiTTL should return true for multi-ttl and ttl-auto")
	}
	if IsMultiTTL("ttl") || IsMultiTTL("wrong-chksum") || IsMultiTTL("none") {
		t.Fatalf("IsMultiTTL should return false for single ttl")
	}

	cfg := DefaultHarnessConfig()
	cfg.FakePacketMode = "multi-ttl"
	cfg.FakeTTL = 4
	cfg.SplitOffset = "sni-mid"
	cfg.AutoLearn = false

	h := NewHarness(cfg)
	defer h.Close()

	domain := "updates.discord.com"
	pkt := buildTestIPv4TCPClientHelloPacket(t, domain, 100000)

	var addr Address
	addr.SetOutbound(true)

	mock := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket multi-ttl: %v", err)
	}

	calls := mock.Calls()
	// In multi-ttl mode, 2 fake packets (TTL 4 + TTL 3) + 2 split segments = 4 packets total
	if len(calls) != 4 {
		t.Fatalf("expected 4 packets from multi-ttl (2 fakes + 2 split segments), got %d", len(calls))
	}

	fake1, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake1: %v", err)
	}
	if fake1.TTL != 4 {
		t.Errorf("fake1 TTL = %d, want 4", fake1.TTL)
	}

	fake2, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse fake2: %v", err)
	}
	if fake2.TTL != 3 {
		t.Errorf("fake2 TTL = %d, want 3", fake2.TTL)
	}

	fi, ttlCount, _, _ := h.FakeStats()
	if fi != 2 || ttlCount != 2 {
		t.Errorf("expected 2 fake packets injected with TTL, got fi=%d, ttlCount=%d", fi, ttlCount)
	}
}

func buildTestPostQuantumClientHello(sni string, extraBytes int) []byte {
	handshakeBody := bytes.Buffer{}

	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x0303))
	handshakeBody.Write(bytes.Repeat([]byte{0x42}, 32))
	handshakeBody.WriteByte(0x00)

	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(4))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0x1301))
	_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(0xc02f))

	handshakeBody.WriteByte(0x01)
	handshakeBody.WriteByte(0x00)

	extensionsBuf := bytes.Buffer{}

	if sni != "" {
		sniData := bytes.Buffer{}
		listLen := uint16(1 + 2 + len(sni))
		_ = binary.Write(&sniData, binary.BigEndian, listLen)
		sniData.WriteByte(0x00)
		_ = binary.Write(&sniData, binary.BigEndian, uint16(len(sni)))
		sniData.WriteString(sni)

		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x0000))
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(sniData.Len()))
		extensionsBuf.Write(sniData.Bytes())
	}

	if extraBytes > 0 {
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(0x0033))
		_ = binary.Write(&extensionsBuf, binary.BigEndian, uint16(extraBytes))
		extensionsBuf.Write(bytes.Repeat([]byte{0x5A}, extraBytes))
	}

	if extensionsBuf.Len() > 0 {
		_ = binary.Write(&handshakeBody, binary.BigEndian, uint16(extensionsBuf.Len()))
		handshakeBody.Write(extensionsBuf.Bytes())
	}

	fullHandshake := bytes.Buffer{}
	fullHandshake.WriteByte(0x01)
	bodyLen := handshakeBody.Len()
	fullHandshake.WriteByte(byte(bodyLen >> 16))
	fullHandshake.WriteByte(byte(bodyLen >> 8))
	fullHandshake.WriteByte(byte(bodyLen & 0xFF))
	fullHandshake.Write(handshakeBody.Bytes())

	record := bytes.Buffer{}
	record.WriteByte(0x16)
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(fullHandshake.Len()))
	record.Write(fullHandshake.Bytes())

	return record.Bytes()
}

func TestHarness_PostQuantumPreSegmentedClientHello(t *testing.T) {
	const sni = "gateway.discord.gg"
	fullPayload := buildTestPostQuantumClientHello(sni, 1850)
	if len(fullPayload) < 1900 {
		t.Fatalf("expected fullPayload >= 1900 bytes, got %d", len(fullPayload))
	}

	// Windows TCP stack pre-segments into Packet 1 (1460 bytes payload)
	packet1Payload := fullPayload[:1460]

	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.SeqNum = 100000
	cfg.AckNum = 2000
	cfg.TCPFlags = packetlab.TCPFlagACK
	cfg.Payload = packet1Payload

	pkt1, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build packet 1: %v", err)
	}

	harnessCfg := DefaultHarnessConfig()
	harnessCfg.FakePacketMode = "ttl"
	harnessCfg.FakeTTL = 4
	harnessCfg.SplitOffset = "sni-mid"
	harnessCfg.AutoLearn = false
	harnessCfg.TargetDomains = []string{"*.discord.gg", "gateway.discord.gg"}

	h := NewHarness(harnessCfg)
	defer h.Close()

	var addr Address
	addr.SetOutbound(true)

	mock := &MockPacketSender{}
	if err := h.HandlePacket(pkt1, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed on pre-segmented packet 1: %v", err)
	}

	// Verify it did NOT hit fallback pass-through
	if h.stats.PassThroughFallbacks.Load() != 0 {
		t.Fatalf("expected 0 PassThroughFallbacks, got %d", h.stats.PassThroughFallbacks.Load())
	}
	if h.stats.PacketsSplit.Load() != 1 {
		t.Fatalf("expected 1 PacketsSplit, got %d", h.stats.PacketsSplit.Load())
	}
	if h.stats.FakePacketsInjected.Load() != 1 {
		t.Fatalf("expected 1 FakePacketsInjected, got %d", h.stats.FakePacketsInjected.Load())
	}

	calls := mock.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 emitted packets (1 fake + 2 split segments), got %d", len(calls))
	}

	fakeParsed, err := packetlab.ParseIPv4TCPPacket(calls[0].Packet)
	if err != nil {
		t.Fatalf("parse fake packet: %v", err)
	}
	if fakeParsed.TTL != 4 {
		t.Errorf("fake packet TTL = %d, want 4", fakeParsed.TTL)
	}

	// Out-of-order split: Segment 2 emitted FIRST
	seg2Parsed, err := packetlab.ParseIPv4TCPPacket(calls[1].Packet)
	if err != nil {
		t.Fatalf("parse segment 2: %v", err)
	}
	// Segment 1 emitted SECOND
	seg1Parsed, err := packetlab.ParseIPv4TCPPacket(calls[2].Packet)
	if err != nil {
		t.Fatalf("parse segment 1: %v", err)
	}

	if seg1Parsed.SeqNum != cfg.SeqNum {
		t.Errorf("segment 1 SeqNum = %d, want %d", seg1Parsed.SeqNum, cfg.SeqNum)
	}
	if seg2Parsed.SeqNum <= seg1Parsed.SeqNum {
		t.Errorf("segment 2 SeqNum (%d) should be > segment 1 SeqNum (%d)", seg2Parsed.SeqNum, seg1Parsed.SeqNum)
	}

	reconstructed := append([]byte(nil), seg1Parsed.Payload...)
	reconstructed = append(reconstructed, seg2Parsed.Payload...)
	if !bytes.Equal(reconstructed, packet1Payload) {
		t.Fatal("reconstructed split segments do not match Packet 1 payload")
	}
}

func TestHarness_LSOSuperPacketClientHello_MTU(t *testing.T) {
	const sni = "gateway.discord.gg"
	fullPayload := buildTestPostQuantumClientHello(sni, 1850)
	if len(fullPayload) < 1900 {
		t.Fatalf("expected fullPayload >= 1900 bytes, got %d", len(fullPayload))
	}

	cfg := packetlab.DefaultPacketConfig()
	cfg.DstPort = 443
	cfg.SeqNum = 200000
	cfg.AckNum = 2000
	cfg.TCPFlags = packetlab.TCPFlagACK | packetlab.TCPFlagPSH
	cfg.Payload = fullPayload

	lsoPkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("build LSO super-packet: %v", err)
	}
	if len(lsoPkt) < 1900 {
		t.Fatalf("expected LSO super-packet > 1900 bytes, got %d", len(lsoPkt))
	}

	harnessCfg := DefaultHarnessConfig()
	harnessCfg.FakePacketMode = "none"
	harnessCfg.SplitOffset = "sni-mid"
	harnessCfg.AutoLearn = false
	harnessCfg.TargetDomains = []string{"*.discord.gg", "gateway.discord.gg"}

	h := NewHarness(harnessCfg)
	defer h.Close()

	var addr Address
	addr.SetOutbound(true)

	mock := &MockPacketSender{}
	if err := h.HandlePacket(lsoPkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket failed on LSO super-packet: %v", err)
	}

	if h.stats.PassThroughFallbacks.Load() != 0 {
		t.Fatalf("expected 0 PassThroughFallbacks, got %d", h.stats.PassThroughFallbacks.Load())
	}
	if h.stats.PacketsSplit.Load() != 1 {
		t.Fatalf("expected 1 PacketsSplit, got %d", h.stats.PacketsSplit.Load())
	}

	calls := mock.Calls()
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 emitted segments for 1950-byte LSO packet, got %d", len(calls))
	}

	// CRITICAL MTU CHECK: verify every single emitted segment is <= 1460 bytes total IP length!
	for i, c := range calls {
		if len(c.Packet) > 1460 {
			t.Errorf("emitted segment %d wire length %d exceeds 1460 bytes MTU limit!", i, len(c.Packet))
		}
		parsedPkt, err := packetlab.ParseIPv4TCPPacket(c.Packet)
		if err != nil {
			t.Errorf("emitted segment %d failed parsing: %v", i, err)
			continue
		}
		ihl := parsedPkt.IHL
		tcpDataOffset := parsedPkt.TCPDataOffset
		actualIPCS := binary.BigEndian.Uint16(c.Packet[10:12])
		expectedIPCS := packetlab.IPv4Checksum(c.Packet[:ihl])
		if actualIPCS != expectedIPCS {
			t.Errorf("emitted segment %d IPv4 checksum mismatch: got 0x%04x, want 0x%04x", i, actualIPCS, expectedIPCS)
		}
		actualTCPCS := binary.BigEndian.Uint16(c.Packet[ihl+16 : ihl+18])
		expectedTCPCS, err := packetlab.TCPChecksum(c.Packet[12:16], c.Packet[16:20], c.Packet[ihl:ihl+tcpDataOffset], parsedPkt.Payload)
		if err != nil || actualTCPCS != expectedTCPCS {
			t.Errorf("emitted segment %d TCP checksum mismatch: got 0x%04x, want 0x%04x, err=%v", i, actualTCPCS, expectedTCPCS, err)
		}
	}

	var seg2Chunks [][]byte
	var seg1Chunks [][]byte
	for _, c := range calls {
		p, err := packetlab.ParseIPv4TCPPacket(c.Packet)
		if err != nil {
			t.Fatalf("parse emitted packet: %v", err)
		}
		if p.SeqNum == cfg.SeqNum {
			seg1Chunks = append(seg1Chunks, p.Payload)
		} else {
			seg2Chunks = append(seg2Chunks, p.Payload)
		}
	}

	var seg1Bytes, seg2Bytes []byte
	for _, b := range seg1Chunks {
		seg1Bytes = append(seg1Bytes, b...)
	}
	for _, b := range seg2Chunks {
		seg2Bytes = append(seg2Bytes, b...)
	}

	reassembled := append(seg1Bytes, seg2Bytes...)
	if !bytes.Equal(reassembled, fullPayload) {
		t.Fatalf("reassembled payload mismatch: len(reassembled)=%d, len(full)=%d", len(reassembled), len(fullPayload))
	}
}

func TestNewHarness_InterceptDNSFilterSelection(t *testing.T) {
	cfgWithDNS := DefaultHarnessConfig()
	cfgWithDNS.InterceptDNS = true
	hWithDNS := NewHarness(cfgWithDNS)
	defer hWithDNS.Close()

	if hWithDNS.Filter() != FilterOutboundWithDNS {
		t.Fatalf("expected FilterOutboundWithDNS (%q), got %q", FilterOutboundWithDNS, hWithDNS.Filter())
	}

	cfgProd := DefaultHarnessConfig()
	cfgProd.InterceptDNS = false
	hProd := NewHarness(cfgProd)
	defer hProd.Close()

	if hProd.Filter() != FilterOutboundProduction {
		t.Fatalf("expected FilterOutboundProduction (%q), got %q", FilterOutboundProduction, hProd.Filter())
	}

	// Also verify with explicitly empty filter strings
	cfgEmptyWithDNS := HarnessConfig{InterceptDNS: true}
	hEmptyWithDNS := NewHarness(cfgEmptyWithDNS)
	defer hEmptyWithDNS.Close()
	if hEmptyWithDNS.Filter() != FilterOutboundWithDNS {
		t.Fatalf("expected FilterOutboundWithDNS with empty filter, got %q", hEmptyWithDNS.Filter())
	}

	cfgEmptyNoDNS := HarnessConfig{InterceptDNS: false}
	hEmptyNoDNS := NewHarness(cfgEmptyNoDNS)
	defer hEmptyNoDNS.Close()
	if hEmptyNoDNS.Filter() != FilterOutboundProduction {
		t.Fatalf("expected FilterOutboundProduction with empty filter, got %q", hEmptyNoDNS.Filter())
	}
}

func TestHarness_InterceptDNS_AAAANoData(t *testing.T) {
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.DNSResolver = &mockDNSResolver{}
	h := NewHarness(cfg)
	defer h.Close()

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeAAAA, 0xABCD)
	if err != nil {
		t.Fatalf("build DNS query: %v", err)
	}

	pkt := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{8, 8, 8, 8}, 53535, queryWire)

	var addr Address
	addr.SetOutbound(true)

	act, replyPkt, err := h.ProcessPacket(pkt, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if act != ActionInterceptDNS {
		t.Fatalf("expected ActionInterceptDNS, got %v", act)
	}
	if replyPkt == nil {
		t.Fatal("expected non-nil synthesized reply packet")
	}

	replyDNSPayload := replyPkt[28:]
	resp, err := dnsdoh.ParseResponse(replyDNSPayload, 0xABCD, "updates.discord.com", dnsdoh.TypeAAAA)
	if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
		t.Fatalf("parse DNS response: %v", err)
	}
	if resp != nil && resp.RCode != dnsdoh.RCodeNoError {
		t.Errorf("expected RCode NoError (0), got %d", resp.RCode)
	}
	if resp != nil && len(resp.IPs) != 0 {
		t.Errorf("expected 0 IPs in NODATA response, got %v", resp.IPs)
	}
}

func TestHarness_InterceptDNS_HandlePacket_AAAANoData(t *testing.T) {
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.DNSResolver = &mockDNSResolver{}
	h := NewHarness(cfg)
	defer h.Close()

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeAAAA, 0x5678)
	if err != nil {
		t.Fatalf("build DNS query: %v", err)
	}

	pkt := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{8, 8, 8, 8}, 53535, queryWire)

	var addr Address
	addr.SetOutbound(true)

	mock := &MockPacketSender{}
	if err := h.HandlePacket(pkt, &addr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 injected response packet, got %d", len(calls))
	}

	injectedAddr := calls[0].Addr
	if injectedAddr.Outbound() {
		t.Error("expected inbound injection (Outbound = false), got Outbound = true")
	}
	if !injectedAddr.IPChecksum() || !injectedAddr.UDPChecksum() {
		t.Error("expected IPChecksum=true and UDPChecksum=true on injected DNS response")
	}

	injectedPkt := calls[0].Packet
	if len(injectedPkt) < 28 {
		t.Fatalf("injected packet too short: %d bytes", len(injectedPkt))
	}

	replyDNSPayload := injectedPkt[28:]
	resp, err := dnsdoh.ParseResponse(replyDNSPayload, 0x5678, "updates.discord.com", dnsdoh.TypeAAAA)
	if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
		t.Fatalf("parse DNS response: %v", err)
	}
	if resp != nil && resp.RCode != dnsdoh.RCodeNoError {
		t.Errorf("expected RCode NoError (0), got %d", resp.RCode)
	}
	if resp != nil && len(resp.IPs) != 0 {
		t.Errorf("expected 0 IPs in NODATA response, got %v", resp.IPs)
	}

	intercepted, resolvedDoH, fallbacks := h.DNSStats()
	if intercepted != 1 {
		t.Errorf("intercepted count = %d, want 1", intercepted)
	}
	if resolvedDoH != 1 {
		t.Errorf("resolvedDoH count = %d, want 1", resolvedDoH)
	}
	if fallbacks != 0 {
		t.Errorf("fallbacks count = %d, want 0", fallbacks)
	}
}

func TestHarness_InterceptDNS_TypeHTTPS_SVCB_NODATA(t *testing.T) {
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.DNSResolver = &mockDNSResolver{}
	h := NewHarness(cfg)
	defer h.Close()

	for _, qtype := range []uint16{dnsdoh.TypeHTTPS, dnsdoh.TypeSVCB} {
		t.Run(fmt.Sprintf("Type_%d", qtype), func(t *testing.T) {
			queryWire, err := dnsdoh.BuildQuery("updates.discord.com", qtype, 0x1234)
			if err != nil {
				t.Fatalf("build DNS query: %v", err)
			}

			pkt := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{8, 8, 8, 8}, 53535, queryWire)
			var addr Address
			addr.SetOutbound(true)

			act, replyPkt, err := h.ProcessPacket(pkt, &addr)
			if err != nil {
				t.Fatalf("ProcessPacket: %v", err)
			}
			if act != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS, got %v", act)
			}
			if replyPkt == nil {
				t.Fatal("expected non-nil synthesized reply packet")
			}

			replyDNSPayload := replyPkt[28:]
			resp, err := dnsdoh.ParseResponse(replyDNSPayload, 0x1234, "updates.discord.com", qtype)
			if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
				t.Fatalf("parse DNS response: %v", err)
			}
			if resp != nil && resp.RCode != dnsdoh.RCodeNoError {
				t.Errorf("expected RCode NoError (0), got %d", resp.RCode)
			}
			if resp != nil && len(resp.IPs) != 0 {
				t.Errorf("expected 0 IPs in NODATA response, got %v", resp.IPs)
			}
		})
	}
}

func TestHarness_InterceptDNS_TargetNonA_CleanNODATA(t *testing.T) {
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.TargetDomains = []string{"updates.discord.com"}
	cfg.DNSResolver = &mockDNSResolver{}
	h := NewHarness(cfg)
	defer h.Close()

	// Type MX = 15, Type TXT = 16
	for _, qtype := range []uint16{15, 16} {
		t.Run(fmt.Sprintf("Type_%d", qtype), func(t *testing.T) {
			queryWire, err := dnsdoh.BuildQuery("updates.discord.com", qtype, 0x9999)
			if err != nil {
				t.Fatalf("build DNS query: %v", err)
			}

			pkt := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{8, 8, 8, 8}, 53535, queryWire)
			var addr Address
			addr.SetOutbound(true)

			act, replyPkt, err := h.ProcessPacket(pkt, &addr)
			if err != nil {
				t.Fatalf("ProcessPacket: %v", err)
			}
			if act != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS, got %v", act)
			}
			if replyPkt == nil {
				t.Fatal("expected non-nil reply packet")
			}

			replyDNSPayload := replyPkt[28:]
			resp, err := dnsdoh.ParseResponse(replyDNSPayload, 0x9999, "updates.discord.com", qtype)
			if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
				t.Fatalf("parse DNS response: %v", err)
			}
			if resp != nil && resp.RCode != dnsdoh.RCodeNoError {
				t.Errorf("expected RCode NoError (0), got %d", resp.RCode)
			}
		})
	}
}

func TestHarness_InterceptDNS_TargetDoHError_SynthesizesSERVFAIL(t *testing.T) {
	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.TargetDomains = []string{"updates.discord.com"}
	cfg.DNSResolver = &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			return nil, 0, false, errors.New("DoH resolution timed out")
		},
	}
	h := NewHarness(cfg)
	defer h.Close()

	queryWire, err := dnsdoh.BuildQuery("updates.discord.com", dnsdoh.TypeA, 0x7777)
	if err != nil {
		t.Fatalf("build DNS query: %v", err)
	}

	pkt := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{8, 8, 8, 8}, 53535, queryWire)
	var addr Address
	addr.SetOutbound(true)

	// 1. In-memory ProcessPacket must return ActionInterceptDNS with SERVFAIL packet (not ActionPassFastPath!)
	act, replyPkt, err := h.ProcessPacket(pkt, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if act != ActionInterceptDNS {
		t.Fatalf("expected ActionInterceptDNS, got %v (leaked to pass-through!)", act)
	}
	if replyPkt == nil {
		t.Fatal("expected synthesized SERVFAIL reply packet")
	}

	replyDNSPayload := replyPkt[28:]
	_, parseErr := dnsdoh.ParseResponse(replyDNSPayload, 0x7777, "updates.discord.com", dnsdoh.TypeA)
	if !errors.Is(parseErr, dnsdoh.ErrServFail) {
		t.Fatalf("expected ErrServFail, got %v", parseErr)
	}

	// 2. Live HandlePacket with mock sender must inject SERVFAIL response and not call pass-through
	mock := &MockPacketSender{}
	var handleAddr Address
	handleAddr.SetOutbound(true)
	if err := h.HandlePacket(pkt, &handleAddr, mock); err != nil {
		t.Fatalf("HandlePacket: %v", err)
	}

	// Wait briefly for goroutine
	time.Sleep(50 * time.Millisecond)

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 injected SERVFAIL response, got %d", len(calls))
	}
	if calls[0].Addr.Outbound() {
		t.Error("expected inbound injection for SERVFAIL response")
	}

	injPayload := calls[0].Packet[28:]
	_, injErr := dnsdoh.ParseResponse(injPayload, 0x7777, "updates.discord.com", dnsdoh.TypeA)
	if !errors.Is(injErr, dnsdoh.ErrServFail) {
		t.Fatalf("expected injected packet to be ErrServFail, got %v", injErr)
	}
}

func TestFastPathInspect_IPv6ExtensionHeaders_DNSAndQUIC(t *testing.T) {
	// 1. Hop-by-Hop (0) with UDP/53
	pktHBH := make([]byte, 40+8+8)
	pktHBH[0] = 0x60
	pktHBH[6] = 0 // NextHeader = Hop-by-Hop
	// Hop-by-Hop header at 40..47
	pktHBH[40] = 17 // NextHeader = UDP
	pktHBH[41] = 0  // Length = (0+1)*8 - 8 = 0 (total 8 bytes)
	// UDP header at 48..55
	binary.BigEndian.PutUint16(pktHBH[48:50], 53535)
	binary.BigEndian.PutUint16(pktHBH[50:52], 53)
	if act, _ := FastPathInspect(pktHBH); act != ActionDropDNSIPv6 {
		t.Errorf("IPv6 HBH + UDP 53: got %s, want ActionDropDNSIPv6", act)
	}

	// 2. Routing (43) with UDP/443
	pktRoute := make([]byte, 40+8+8)
	pktRoute[0] = 0x60
	pktRoute[6] = 43 // NextHeader = Routing
	// Routing header at 40..47
	pktRoute[40] = 17 // NextHeader = UDP
	pktRoute[41] = 0  // Length = 8 bytes
	// UDP header at 48..55
	binary.BigEndian.PutUint16(pktRoute[48:50], 53535)
	binary.BigEndian.PutUint16(pktRoute[50:52], 443)
	if act, _ := FastPathInspect(pktRoute); act != ActionDropQUIC {
		t.Errorf("IPv6 Routing + UDP 443: got %s, want ActionDropQUIC", act)
	}

	// 3. Destination Options (60) with UDP/53
	pktDstOpt := make([]byte, 40+8+8)
	pktDstOpt[0] = 0x60
	pktDstOpt[6] = 60 // NextHeader = Destination Options
	pktDstOpt[40] = 17
	pktDstOpt[41] = 0
	binary.BigEndian.PutUint16(pktDstOpt[48:50], 53535)
	binary.BigEndian.PutUint16(pktDstOpt[50:52], 53)
	if act, _ := FastPathInspect(pktDstOpt); act != ActionDropDNSIPv6 {
		t.Errorf("IPv6 Destination Options + UDP 53: got %s, want ActionDropDNSIPv6", act)
	}

	// 4. Fragment Header (44) with UDP/53
	pktFrag := make([]byte, 40+8+8)
	pktFrag[0] = 0x60
	pktFrag[6] = 44 // NextHeader = Fragment
	pktFrag[40] = 17
	pktFrag[41] = 0
	binary.BigEndian.PutUint16(pktFrag[42:44], 0) // offset 0
	binary.BigEndian.PutUint16(pktFrag[48:50], 53535)
	binary.BigEndian.PutUint16(pktFrag[50:52], 53)
	if act, _ := FastPathInspect(pktFrag); act != ActionDropDNSIPv6 {
		t.Errorf("IPv6 Fragment + UDP 53: got %s, want ActionDropDNSIPv6", act)
	}
}

func TestHarness_MatchesTarget(t *testing.T) {
	root := filepath.Join("..", "..")
	cfgPath := filepath.Join(root, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config.json: %v", err)
	}

	matcher, err := config.NewDomainMatcher(cfg.DomainRules)
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}

	hCfg := DefaultHarnessConfig()
	hCfg.DefaultProfile = cfg.DefaultProfile
	hCfg.DomainMatcher = matcher
	hCfg.ExcludedHostnames = []string{"cloudflare-dns.com", "dns.google", "one.one.one.one"}

	h := NewHarness(hCfg)
	defer h.Close()

	shouldMatch := []string{
		"updates.discord.com",
		"discord.com",
		"gateway.discord.gg",
		"dl.discordapp.net",
		"status.discord.com",
		"images.discord.media",
		"voice.discord.co",
		"www.roblox.com",
		"t1.rbxcdn.com",
		"arbitrary-unlisted-domain.org",
		"UPDATES.DISCORD.COM",
		"updates.discord.com.",
	}

	for _, d := range shouldMatch {
		if !h.matchesTarget(d) {
			t.Errorf("expected matchesTarget(%q) == true, got false", d)
		}
	}

	shouldNotMatch := []string{
		"",
		"cloudflare-dns.com",
		"dns.google",
		"one.one.one.one",
		"CLOUDFLARE-DNS.COM.",
	}

	for _, d := range shouldNotMatch {
		if h.matchesTarget(d) {
			t.Errorf("expected matchesTarget(%q) == false, got true", d)
		}
	}
}

func TestHarness_ProcessPacket_InboundIPv6NotDropped(t *testing.T) {
	hCfg := DefaultHarnessConfig()
	hCfg.InterceptDNS = true
	h := NewHarness(hCfg)
	defer h.Close()

	// 1. Inbound IPv6 TCP 443 packet (addr.Outbound = false) must NOT be dropped
	pktIPv6TCP := make([]byte, 40+20)
	pktIPv6TCP[0] = 0x60
	pktIPv6TCP[6] = 6 // TCP
	binary.BigEndian.PutUint16(pktIPv6TCP[40:42], 54321)
	binary.BigEndian.PutUint16(pktIPv6TCP[42:44], 443) // dstPort = 443

	var inboundAddr Address
	inboundAddr.SetOutbound(false)
	inboundAddr.SetIPv6(true)

	act, outPkt, err := h.ProcessPacket(pktIPv6TCP, &inboundAddr)
	if err != nil {
		t.Fatalf("ProcessPacket on inbound IPv6 TCP: %v", err)
	}
	if act != ActionPassFastPath || outPkt == nil {
		t.Fatalf("inbound IPv6 TCP was dropped! act=%v, outPkt=%v", act, outPkt)
	}

	// 2. Inbound IPv6 UDP 53 packet (addr.Outbound = false) must NOT be dropped
	pktIPv6UDP := make([]byte, 40+8)
	pktIPv6UDP[0] = 0x60
	pktIPv6UDP[6] = 17 // UDP
	binary.BigEndian.PutUint16(pktIPv6UDP[40:42], 54321)
	binary.BigEndian.PutUint16(pktIPv6UDP[42:44], 53)

	actUDP, outPktUDP, errUDP := h.ProcessPacket(pktIPv6UDP, &inboundAddr)
	if errUDP != nil {
		t.Fatalf("ProcessPacket on inbound IPv6 UDP: %v", errUDP)
	}
	if actUDP != ActionPassFastPath || outPktUDP == nil {
		t.Fatalf("inbound IPv6 UDP was dropped! act=%v, outPkt=%v", actUDP, outPktUDP)
	}
}

func TestNewHarness_AutoInitResolverWhenInterceptDNS(t *testing.T) {
	hCfg := HarnessConfig{
		InterceptDNS: true,
		DNSResolver:  nil,
		DoHResolver:  nil,
	}

	h := NewHarness(hCfg)
	defer h.Close()

	if h.cfg.DNSResolver == nil {
		t.Fatal("expected NewHarness to auto-initialize non-nil DNSResolver when InterceptDNS is true")
	}
	if h.cfg.DoHResolver == nil {
		t.Fatal("expected NewHarness to auto-initialize non-nil DoHResolver when InterceptDNS is true")
	}
	if h.cfg.Filter != FilterOutboundWithDNS {
		t.Fatalf("expected FilterOutboundWithDNS (%q), got %q", FilterOutboundWithDNS, h.cfg.Filter)
	}
}

func TestHandleCandidateFragmentation_SNILessPacket1(t *testing.T) {
	// Build minimal valid ClientHello preamble without SNI (55 bytes)
	// TLS Record Header: 0x16 0x03 0x01 (len 50)
	// Handshake: 0x01 (len 46) 0x03 0x03 (TLS 1.2 client version)
	rawPayload := make([]byte, 55)
	rawPayload[0] = 0x16 // Handshake
	rawPayload[1] = 0x03
	rawPayload[2] = 0x01
	binary.BigEndian.PutUint16(rawPayload[3:5], 50)
	rawPayload[5] = 0x01 // ClientHello
	// Handshake length (3 bytes)
	rawPayload[6] = 0
	rawPayload[7] = 0
	rawPayload[8] = 46
	rawPayload[9] = 0x03
	rawPayload[10] = 0x03 // TLS 1.2

	// Build IPv4 TCP packet with destination 104.16.1.1:443 (non-DoH IP)
	cfg := packetlab.DefaultPacketConfig()
	cfg.DstIP = [4]byte{104, 16, 1, 1}
	cfg.DstPort = 443
	cfg.Payload = rawPayload
	pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket: %v", err)
	}

	var sentPackets [][]byte
	sender := PacketSenderFunc(func(p []byte, a *Address) (int, error) {
		cloned := make([]byte, len(p))
		copy(cloned, p)
		sentPackets = append(sentPackets, cloned)
		return len(p), nil
	})

	h := NewHarness(HarnessConfig{
		DefaultProfile: "packet-default",
		FakePacketMode: "ttl",
		FakeTTL:        4,
		SplitOffset:    "sni-mid",
		Sender:         sender,
	})
	defer h.Close()

	var addr Address
	addr.SetOutbound(true)

	// Process SNI-less packet 1 with default desync active
	act, _, err := h.ProcessPacket(pkt, &addr)
	if err != nil {
		t.Fatalf("ProcessPacket: %v", err)
	}
	if act != ActionInspectCandidate {
		t.Fatalf("expected ActionInspectCandidate, got %v", act)
	}

	// Must have injected: 1 Fake Packet + 2 Out-of-order split segments = 3 packets total
	if len(sentPackets) != 3 {
		t.Fatalf("expected 3 sent packets (1 fake + 2 split), got %d", len(sentPackets))
	}

	// Verify fake packet has TTL=4 and benign SNI www.example.com
	fakePkt := sentPackets[0]
	if fakePkt[8] != 4 {
		t.Errorf("fake packet TTL=%d, want 4", fakePkt[8])
	}

	// Verify segment 2 was sent before segment 1 (split offset 2)
	seg2 := sentPackets[1]
	seg1 := sentPackets[2]
	seg1Parsed, err := packetlab.ParseIPv4TCPPacket(seg1)
	if err != nil {
		t.Fatalf("parse seg1: %v", err)
	}
	seg2Parsed, err := packetlab.ParseIPv4TCPPacket(seg2)
	if err != nil {
		t.Fatalf("parse seg2: %v", err)
	}
	if len(seg1Parsed.Payload) != 2 {
		t.Errorf("expected seg1 payload len 2, got %d", len(seg1Parsed.Payload))
	}
	if len(seg2Parsed.Payload) != len(rawPayload)-2 {
		t.Errorf("expected seg2 payload len %d, got %d", len(rawPayload)-2, len(seg2Parsed.Payload))
	}

	// Now test DoH bootstrap IP exclusion (1.1.1.1): FastPathInspect and ProcessPacket return ActionPassFastPath!
	cfg.DstIP = [4]byte{1, 1, 1, 1}
	pktBootstrap, err := packetlab.BuildIPv4TCPPacket(cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket bootstrap: %v", err)
	}
	sentPackets = nil

	actBootstrap, outBootstrap, errBootstrap := h.ProcessPacket(pktBootstrap, &addr)
	if errBootstrap != nil {
		t.Fatalf("ProcessPacket DoH bootstrap: %v", errBootstrap)
	}
	if actBootstrap != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath, got %v", actBootstrap)
	}
	if !bytes.Equal(outBootstrap, pktBootstrap) {
		t.Fatal("expected pass-through packet to be identical to original")
	}

	if err := h.HandlePacket(pktBootstrap, &addr, sender); err != nil {
		t.Fatalf("HandlePacket DoH bootstrap: %v", err)
	}
	if len(sentPackets) != 1 {
		t.Fatalf("expected 1 pass-through packet for DoH bootstrap IP, got %d", len(sentPackets))
	}
	if !bytes.Equal(sentPackets[0], pktBootstrap) {
		t.Fatal("expected pass-through packet to be identical to original")
	}
}

func TestFilterOutboundIPv6TCPSYN(t *testing.T) {
	dll, err := syscall.LoadDLL(filepath.Join("..", "..", "WinDivert.dll"))
	if err != nil {
		t.Skipf("WinDivert.dll not available for eval test: %v", err)
	}
	defer dll.Release()

	evalFilterProc, err := dll.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatalf("FindProc EvalFilter: %v", err)
	}

	filter := FilterOutboundWithDNS
	filterPtr, _ := syscall.BytePtrFromString(filter)

	// Build IPv6 TCP SYN packet to port 443 (PayloadLength == 0)
	pkt := make([]byte, 40+20)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20)      // PayloadLength in IPv6 header is the TCP header length (20)
	pkt[6] = 6                                    // TCP
	binary.BigEndian.PutUint16(pkt[40:42], 54321) // srcPort
	binary.BigEndian.PutUint16(pkt[42:44], 443)   // dstPort
	pkt[52] = 0x50                                // TCP data offset 5 (20 bytes)
	pkt[53] = 0x02                                // SYN flag (bit 1)

	var addr Address
	addr.SetOutbound(true)
	addr.SetLoopback(false)
	addr.SetImpostor(false)
	addr.SetIPv6(true)

	rEval, _, _ := evalFilterProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if rEval == 0 {
		t.Errorf("FilterOutboundWithDNS failed to match IPv6 TCP SYN! Evaluated to FALSE!")
	} else {
		t.Logf("FilterOutboundWithDNS successfully evaluated to TRUE on IPv6 TCP SYN packet!")
	}
}

func TestHarness_DiscordUpdaterDomainsInterceptionAndDesync(t *testing.T) {
	cfgPath := filepath.Join("..", "..", "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load config.json: %v", err)
	}

	matcher, err := config.NewDomainMatcher(cfg.DomainRules)
	if err != nil {
		t.Fatalf("NewDomainMatcher: %v", err)
	}

	hCfg := DefaultHarnessConfig()
	hCfg.InterceptDNS = true
	hCfg.DomainMatcher = matcher
	hCfg.FakePacketMode = cfg.Packet.FakePacketMode
	hCfg.FakeTTL = uint8(cfg.Packet.FakeTTL)
	hCfg.SplitOffset = cfg.Packet.SplitOffset
	hCfg.DefaultProfile = cfg.DefaultProfile

	discordIP := net.ParseIP("162.159.135.232")
	mockResolver := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			if qtype == dnsdoh.TypeA {
				return []net.IP{discordIP}, 60 * time.Second, false, nil
			}
			return nil, 60 * time.Second, true, nil
		},
	}
	hCfg.DNSResolver = mockResolver

	h := NewHarness(hCfg)
	defer h.Close()

	testDomains := []string{
		"updates.discord.com",
		"stable.dl2.discordapp.net",
		"dl.discordapp.net",
		"cdn.discordapp.com",
		"gateway.discord.gg",
		"discord.com",
		"discordapp.net",
	}

	for _, domain := range testDomains {
		t.Run("Target_"+domain, func(t *testing.T) {
			if !h.matchesExplicitTarget(domain) {
				t.Fatalf("expected matchesExplicitTarget(%q) to be true", domain)
			}

			// 1. Type AAAA (IPv6) query -> Clean NODATA
			queryAAAA, err := dnsdoh.BuildQuery(domain, dnsdoh.TypeAAAA, 0x1111)
			if err != nil {
				t.Fatalf("BuildQuery AAAA: %v", err)
			}
			pktAAAA := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{192, 168, 1, 1}, 53535, queryAAAA)
			var addrAAAA Address
			addrAAAA.SetOutbound(true)

			act, replyPkt, err := h.ProcessPacket(pktAAAA, &addrAAAA)
			if err != nil {
				t.Fatalf("ProcessPacket AAAA: %v", err)
			}
			if act != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS, got %v", act)
			}
			if replyPkt == nil {
				t.Fatal("expected synthesized reply packet for AAAA, got nil")
			}
			respAAAA, err := dnsdoh.ParseResponse(replyPkt[28:], 0x1111, domain, dnsdoh.TypeAAAA)
			if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
				t.Fatalf("parse AAAA response: %v", err)
			}
			if respAAAA != nil && (respAAAA.RCode != dnsdoh.RCodeNoError || len(respAAAA.IPs) != 0) {
				t.Errorf("expected clean NODATA for AAAA, got rcode=%d, ips=%v", respAAAA.RCode, respAAAA.IPs)
			}

			// 2. Type HTTPS (65) query -> Clean NODATA
			queryHTTPS, err := dnsdoh.BuildQuery(domain, dnsdoh.TypeHTTPS, 0x2222)
			if err != nil {
				t.Fatalf("BuildQuery HTTPS: %v", err)
			}
			pktHTTPS := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{192, 168, 1, 1}, 53536, queryHTTPS)
			var addrHTTPS Address
			addrHTTPS.SetOutbound(true)

			act, replyHTTPS, err := h.ProcessPacket(pktHTTPS, &addrHTTPS)
			if err != nil {
				t.Fatalf("ProcessPacket HTTPS: %v", err)
			}
			if act != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS, got %v", act)
			}
			if replyHTTPS == nil {
				t.Fatal("expected synthesized reply packet for HTTPS, got nil")
			}
			respHTTPS, err := dnsdoh.ParseResponse(replyHTTPS[28:], 0x2222, domain, dnsdoh.TypeHTTPS)
			if err != nil && !errors.Is(err, dnsdoh.ErrNoData) {
				t.Fatalf("parse HTTPS response: %v", err)
			}
			if respHTTPS != nil && (respHTTPS.RCode != dnsdoh.RCodeNoError || len(respHTTPS.IPs) != 0) {
				t.Errorf("expected clean NODATA for HTTPS, got rcode=%d, ips=%v", respHTTPS.RCode, respHTTPS.IPs)
			}

			// 3. Type A (1) query -> Synthesized DoH answer
			queryA, err := dnsdoh.BuildQuery(domain, dnsdoh.TypeA, 0x3333)
			if err != nil {
				t.Fatalf("BuildQuery A: %v", err)
			}
			pktA := buildTestUDP53QueryPacket([4]byte{192, 168, 1, 50}, [4]byte{192, 168, 1, 1}, 53537, queryA)
			var addrA Address
			addrA.SetOutbound(true)

			act, replyA, err := h.ProcessPacket(pktA, &addrA)
			if err != nil {
				t.Fatalf("ProcessPacket A: %v", err)
			}
			if act != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS, got %v", act)
			}
			if replyA == nil {
				t.Fatal("expected synthesized reply packet for A, got nil")
			}
			respA, err := dnsdoh.ParseResponse(replyA[28:], 0x3333, domain, dnsdoh.TypeA)
			if err != nil {
				t.Fatalf("parse A response: %v", err)
			}
			if len(respA.IPs) != 1 || !respA.IPs[0].Equal(discordIP) {
				t.Errorf("expected IP %v, got %v", discordIP, respA.IPs)
			}

			// 4. Target DoH failure -> Synthesize RFC 1035 SERVFAIL (no leak to ISP)
			failingResolver := &mockDNSResolver{
				resolveFn: func(ctx context.Context, d string, qt uint16) ([]net.IP, time.Duration, bool, error) {
					return nil, 0, false, errors.New("DoH upstream connection timed out")
				},
			}
			hFailCfg := hCfg
			hFailCfg.DNSResolver = failingResolver
			hFail := NewHarness(hFailCfg)
			defer hFail.Close()

			var addrFail Address
			addrFail.SetOutbound(true)

			actFail, replyFail, errFail := hFail.ProcessPacket(pktA, &addrFail)
			if errFail != nil {
				t.Fatalf("ProcessPacket target DoH failure: %v", errFail)
			}
			if actFail != ActionInterceptDNS {
				t.Fatalf("expected ActionInterceptDNS on DoH failure for target %q, got %v", domain, actFail)
			}
			if replyFail == nil {
				t.Fatalf("expected synthesized SERVFAIL response packet, got nil")
			}
			_, sfErr := dnsdoh.ParseResponse(replyFail[28:], 0x3333, domain, dnsdoh.TypeA)
			if !errors.Is(sfErr, dnsdoh.ErrServFail) {
				t.Errorf("expected ErrServFail, got %v", sfErr)
			}

			// 5. TLS ClientHello on port 443 -> Out-of-Order Split + Fake Packet desync
			var sentPackets [][]byte
			hDesyncCfg := hCfg
			hDesyncCfg.Sender = PacketSenderFunc(func(p []byte, a *Address) (int, error) {
				cloned := make([]byte, len(p))
				copy(cloned, p)
				sentPackets = append(sentPackets, cloned)
				return len(p), nil
			})
			hDesync := NewHarness(hDesyncCfg)
			defer hDesync.Close()

			chPayload := packetlab.BuildDummyClientHello(domain)
			tcpCfg := packetlab.DefaultPacketConfig()
			tcpCfg.DstIP = [4]byte{162, 159, 135, 232}
			tcpCfg.DstPort = 443
			tcpCfg.Payload = chPayload
			pktTLS, err := packetlab.BuildIPv4TCPPacket(tcpCfg)
			if err != nil {
				t.Fatalf("BuildIPv4TCPPacket TLS: %v", err)
			}

			var addrTLS Address
			addrTLS.SetOutbound(true)

			actTLS, _, errTLS := hDesync.ProcessPacket(pktTLS, &addrTLS)
			if errTLS != nil {
				t.Fatalf("ProcessPacket TLS: %v", errTLS)
			}
			if actTLS != ActionInspectCandidate {
				t.Fatalf("expected ActionInspectCandidate for TLS ClientHello to %q, got %v", domain, actTLS)
			}
			if len(sentPackets) != 3 {
				t.Fatalf("expected 3 desynced packets (1 fake + 2 split), got %d", len(sentPackets))
			}
			if sentPackets[0][8] != 4 {
				t.Errorf("fake packet TTL = %d, want 4", sentPackets[0][8])
			}
		})
	}
}

func TestMultiPacketPostQuantumClientHelloDesync(t *testing.T) {
	var sentPackets [][]byte

	cfg := DefaultHarnessConfig()
	cfg.TargetDomains = []string{"gateway.discord.gg"}
	cfg.FakePacketMode = "ttl"
	cfg.FakeTTL = 4
	cfg.Sender = PacketSenderFunc(func(p []byte, a *Address) (int, error) {
		cloned := make([]byte, len(p))
		copy(cloned, p)
		sentPackets = append(sentPackets, cloned)
		return len(p), nil
	})
	h := NewHarness(cfg)
	defer h.Close()

	// 1. Build Packet 1 payload (1,460 bytes)
	// Declared TLS record length: 1,900 bytes (> 1,460).
	// Extension block does not contain SNI extension (sni == "").
	p1Payload := make([]byte, 1460)
	p1Payload[0] = 0x16 // Handshake
	p1Payload[1] = 0x03 // TLS 1.0 record version
	p1Payload[2] = 0x01
	binary.BigEndian.PutUint16(p1Payload[3:5], 1900) // Record length = 1900 > 1460
	p1Payload[5] = 0x01                              // ClientHello
	p1Payload[6] = 0x00                              // Handshake length = 1896
	p1Payload[7] = 0x07
	p1Payload[8] = 0x68
	p1Payload[9] = 0x03 // Version 1.2
	p1Payload[10] = 0x03
	// 32 bytes random (bytes 11..42)
	for i := 11; i < 43; i++ {
		p1Payload[i] = 0xAA
	}
	p1Payload[43] = 0                               // Session ID len = 0
	binary.BigEndian.PutUint16(p1Payload[44:46], 4) // Cipher suites len = 4
	binary.BigEndian.PutUint16(p1Payload[46:48], 0x1301)
	binary.BigEndian.PutUint16(p1Payload[48:50], 0xc02f)
	p1Payload[50] = 1 // Compression methods len = 1
	p1Payload[51] = 0
	binary.BigEndian.PutUint16(p1Payload[52:54], 1800) // Extensions length = 1800
	// Bytes 54..1459 are large post-quantum key shares (dummy data without SNI)
	for i := 54; i < len(p1Payload); i++ {
		p1Payload[i] = 0x55
	}

	srcIP := [4]byte{192, 168, 1, 100}
	dstIP := [4]byte{162, 159, 135, 234}
	srcPort := uint16(54321)
	dstPort := uint16(443)
	seq1 := uint32(100000)

	tcpCfg1 := packetlab.DefaultPacketConfig()
	tcpCfg1.SrcIP = srcIP
	tcpCfg1.DstIP = dstIP
	tcpCfg1.SrcPort = srcPort
	tcpCfg1.DstPort = dstPort
	tcpCfg1.SeqNum = seq1
	tcpCfg1.Payload = p1Payload

	pkt1, err := packetlab.BuildIPv4TCPPacket(tcpCfg1)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket pkt1: %v", err)
	}

	var addr1 Address
	addr1.SetOutbound(true)

	act1, _, err1 := h.ProcessPacket(pkt1, &addr1)
	if err1 != nil {
		t.Fatalf("ProcessPacket pkt1: %v", err1)
	}
	if act1 != ActionInspectCandidate {
		t.Fatalf("expected ActionInspectCandidate for pkt1, got %v", act1)
	}

	// Verify Packet 1 was desynced: 1 fake packet + out-of-order split segments
	// Segment 2 (1,458 bytes) is subsegmented into 1400 + 58 bytes to respect MaxSegmentPayload, plus 2-byte Segment 1
	if len(sentPackets) != 4 {
		t.Fatalf("expected 4 packets sent for Packet 1, got %d", len(sentPackets))
	}
	fakePkt1 := sentPackets[0]
	if fakePkt1[8] != 4 {
		t.Errorf("Packet 1 fake packet TTL = %d, want 4", fakePkt1[8])
	}
	fakeSeq1 := binary.BigEndian.Uint32(fakePkt1[24:28])
	if fakeSeq1 != seq1 {
		t.Errorf("Packet 1 fake packet SeqNum = %d, want %d", fakeSeq1, seq1)
	}
	p1Suffix := sentPackets[1]
	p1Prefix := sentPackets[3]
	p1SuffixSeq := binary.BigEndian.Uint32(p1Suffix[24:28])
	p1PrefixSeq := binary.BigEndian.Uint32(p1Prefix[24:28])
	if p1PrefixSeq != seq1 {
		t.Errorf("Packet 1 prefix SeqNum = %d, want %d", p1PrefixSeq, seq1)
	}
	if p1SuffixSeq <= p1PrefixSeq {
		t.Errorf("Packet 1 suffix SeqNum (%d) must be greater than prefix SeqNum (%d)", p1SuffixSeq, p1PrefixSeq)
	}
	if h.stats.PacketsSplit.Load() != 1 {
		t.Errorf("expected PacketsSplit = 1 after Packet 1, got %d", h.stats.PacketsSplit.Load())
	}

	expectedNextSeq := seq1 + uint32(len(p1Payload))

	// 2. Build Packet 2 payload (440 bytes)
	// Contains the SNI extension for "gateway.discord.gg"
	sniDomain := "gateway.discord.gg"
	sniBytes := []byte(sniDomain)
	p2Payload := make([]byte, 440)
	for i := range p2Payload {
		p2Payload[i] = 0x66
	}

	// Embed SNI extension at offset 30 in Packet 2
	sniExtOffset := 30
	binary.BigEndian.PutUint16(p2Payload[sniExtOffset:sniExtOffset+2], 0x0000) // Type: server_name
	extLen := uint16(len(sniBytes) + 5)
	listLen := uint16(len(sniBytes) + 3)
	binary.BigEndian.PutUint16(p2Payload[sniExtOffset+2:sniExtOffset+4], extLen)
	binary.BigEndian.PutUint16(p2Payload[sniExtOffset+4:sniExtOffset+6], listLen)
	p2Payload[sniExtOffset+6] = 0x00 // host_name
	binary.BigEndian.PutUint16(p2Payload[sniExtOffset+7:sniExtOffset+9], uint16(len(sniBytes)))
	copy(p2Payload[sniExtOffset+9:], sniBytes)

	tcpCfg2 := packetlab.DefaultPacketConfig()
	tcpCfg2.SrcIP = srcIP
	tcpCfg2.DstIP = dstIP
	tcpCfg2.SrcPort = srcPort
	tcpCfg2.DstPort = dstPort
	tcpCfg2.SeqNum = expectedNextSeq
	tcpCfg2.Payload = p2Payload

	pkt2, err := packetlab.BuildIPv4TCPPacket(tcpCfg2)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket pkt2: %v", err)
	}

	sentPackets = nil

	var addr2 Address
	addr2.SetOutbound(true)

	act2, _, err2 := h.ProcessPacket(pkt2, &addr2)
	if err2 != nil {
		t.Fatalf("ProcessPacket pkt2: %v", err2)
	}
	if act2 != ActionInspectCandidate {
		t.Fatalf("expected ActionInspectCandidate for pkt2, got %v", act2)
	}

	// Verify Packet2Desynced counter incremented and PacketsSplit now 2
	if h.stats.Packet2Desynced.Load() != 1 {
		t.Errorf("expected Packet2Desynced = 1, got %d", h.stats.Packet2Desynced.Load())
	}
	if h.stats.PacketsSplit.Load() != 2 {
		t.Errorf("expected PacketsSplit = 2 after Packet 2, got %d", h.stats.PacketsSplit.Load())
	}

	// Verify exactly 3 packets sent for Packet 2: 1 fake + 2 split
	if len(sentPackets) != 3 {
		t.Fatalf("expected 3 packets sent for Packet 2, got %d", len(sentPackets))
	}

	// Fake packet checks
	fakePkt := sentPackets[0]
	fakeTTL := fakePkt[8]
	if fakeTTL != 4 {
		t.Errorf("fake packet TTL = %d, want 4", fakeTTL)
	}
	fakeSeq := binary.BigEndian.Uint32(fakePkt[24:28])
	if fakeSeq != expectedNextSeq {
		t.Errorf("fake packet SeqNum = %d, want %d", fakeSeq, expectedNextSeq)
	}
	fakePayloadLen := len(fakePkt) - 40
	if fakePayloadLen != len(p2Payload) {
		t.Errorf("fake packet payload len = %d, want %d", fakePayloadLen, len(p2Payload))
	}

	// Out-of-order split checks
	suffixPkt := sentPackets[1]
	prefixPkt := sentPackets[2]

	suffixSeq := binary.BigEndian.Uint32(suffixPkt[24:28])
	prefixSeq := binary.BigEndian.Uint32(prefixPkt[24:28])

	if prefixSeq != expectedNextSeq {
		t.Errorf("prefix packet SeqNum = %d, want %d", prefixSeq, expectedNextSeq)
	}
	if suffixSeq <= prefixSeq {
		t.Errorf("suffix packet SeqNum (%d) must be greater than prefix SeqNum (%d)", suffixSeq, prefixSeq)
	}
	splitOffset := int(suffixSeq - prefixSeq)
	prefixPayloadLen := len(prefixPkt) - 40
	suffixPayloadLen := len(suffixPkt) - 40

	if prefixPayloadLen != splitOffset {
		t.Errorf("prefix payload len = %d, want %d", prefixPayloadLen, splitOffset)
	}
	if prefixPayloadLen+suffixPayloadLen != len(p2Payload) {
		t.Errorf("sum of split payloads %d != %d", prefixPayloadLen+suffixPayloadLen, len(p2Payload))
	}

	// Verify entry was removed from tracker
	if h.pqTracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, expectedNextSeq) {
		t.Errorf("pqTracker still held matched entry")
	}
}

func TestPQPacketTracker_NonMatchingSeqNotEvicted(t *testing.T) {
	tracker := newPQPacketTracker()
	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := [4]byte{162, 159, 135, 234}
	srcPort := uint16(54321)
	dstPort := uint16(443)
	nextSeq := uint32(100000)

	tracker.Record(srcIP, dstIP, srcPort, dstPort, nextSeq)

	// 1. Non-matching sequence number (e.g. retransmission of Packet 1 or intermediate ACK)
	if tracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, 99999) {
		t.Fatal("expected MatchAndRemove with wrong seq to return false")
	}

	// 2. Verify entry is still retained in tracker after non-matching lookup!
	if !tracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, nextSeq) {
		t.Fatal("expected MatchAndRemove with correct seq to return true after earlier non-matching query")
	}

	// 3. Once matched, entry is now removed
	if tracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, nextSeq) {
		t.Fatal("expected MatchAndRemove on already-consumed entry to return false")
	}
}

func TestScriptFilesEncoding_7BitASCII(t *testing.T) {
	scripts := []string{
		"../../launch-discord.bat",
		"../../start-bypass.bat",
		"../../stop-and-recover.bat",
	}

	for _, relPath := range scripts {
		absPath, err := filepath.Abs(relPath)
		if err != nil {
			t.Fatalf("resolve abs path for %s: %v", relPath, err)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			t.Fatalf("read file %s: %v", absPath, err)
		}
		for idx, b := range data {
			if b > 127 {
				t.Fatalf("file %s contains non-ASCII byte 0x%02X at offset %d", filepath.Base(absPath), b, idx)
			}
		}
	}
}

func TestIPv6DNSDoHInterception(t *testing.T) {
	mockResolver := &mockDNSResolver{
		resolveFn: func(ctx context.Context, domain string, qtype uint16) ([]net.IP, time.Duration, bool, error) {
			if strings.EqualFold(strings.TrimSuffix(domain, "."), "discord.com") && qtype == dnsdoh.TypeA {
				return []net.IP{net.ParseIP("162.159.135.232")}, 60 * time.Second, false, nil
			}
			return nil, 60 * time.Second, true, nil
		},
	}

	cfg := DefaultHarnessConfig()
	cfg.InterceptDNS = true
	cfg.DNSResolver = mockResolver
	cfg.TargetDomains = []string{"discord.com"}
	h := NewHarness(cfg)
	defer h.Close()

	srcIP := net.ParseIP("2001:db8::100").To16()
	dstIP := net.ParseIP("2001:4860:4860::8888").To16()
	srcPort := uint16(54321)
	dstPort := uint16(53)

	// 1. Outbound IPv6 DNS Query for discord.com Type A
	qA := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'd', 'i', 's', 'c', 'o', 'r', 'd', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	pktA := make([]byte, 40+8+len(qA))
	pktA[0] = 0x60
	binary.BigEndian.PutUint16(pktA[4:6], uint16(8+len(qA)))
	pktA[6] = 17 // UDP
	pktA[7] = 64
	copy(pktA[8:24], srcIP)
	copy(pktA[24:40], dstIP)
	binary.BigEndian.PutUint16(pktA[40:42], srcPort)
	binary.BigEndian.PutUint16(pktA[42:44], dstPort)
	binary.BigEndian.PutUint16(pktA[44:46], uint16(8+len(qA)))
	copy(pktA[48:], qA)

	var addrA Address
	addrA.SetOutbound(true)
	addrA.SetIPv6(true)

	actA, replyA, errA := h.ProcessPacket(pktA, &addrA)
	if errA != nil {
		t.Fatalf("ProcessPacket IPv6 DNS Type A: %v", errA)
	}
	if actA != ActionDropDNSIPv6 {
		t.Fatalf("expected ActionDropDNSIPv6, got %v", actA)
	}
	if replyA == nil {
		t.Fatalf("expected synthesized IPv6 response packet, got nil")
	}
	if addrA.Outbound() {
		t.Errorf("expected addr.Outbound() = false")
	}
	if !addrA.IPv6() {
		t.Errorf("expected addr.IPv6() = true")
	}
	if !addrA.UDPChecksum() {
		t.Errorf("expected addr.UDPChecksum() = true")
	}

	if replyA[0]>>4 != 6 {
		t.Errorf("expected IPv6 version 6, got %d", replyA[0]>>4)
	}
	if !bytes.Equal(replyA[8:24], dstIP) {
		t.Errorf("expected SrcIP = original DstIP (%s), got %s", dstIP, net.IP(replyA[8:24]))
	}
	if !bytes.Equal(replyA[24:40], srcIP) {
		t.Errorf("expected DstIP = original SrcIP (%s), got %s", srcIP, net.IP(replyA[24:40]))
	}
	replySrcPort := binary.BigEndian.Uint16(replyA[40:42])
	replyDstPort := binary.BigEndian.Uint16(replyA[42:44])
	if replySrcPort != 53 || replyDstPort != srcPort {
		t.Errorf("expected reply ports 53 -> %d, got %d -> %d", srcPort, replySrcPort, replyDstPort)
	}

	parsedA, pErrA := dnsdoh.ParseResponse(replyA[48:], 0x1234, "discord.com", dnsdoh.TypeA)
	if pErrA != nil {
		t.Fatalf("ParseResponse Type A: %v", pErrA)
	}
	if len(parsedA.IPs) != 1 || !parsedA.IPs[0].Equal(net.ParseIP("162.159.135.232")) {
		t.Errorf("expected IP 162.159.135.232, got %v", parsedA.IPs)
	}

	// 2. Outbound IPv6 DNS Query for discord.com Type AAAA (Type 28) -> Clean NODATA
	qAAAA := []byte{
		0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'd', 'i', 's', 'c', 'o', 'r', 'd', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x1c, 0x00, 0x01,
	}
	pktAAAA := make([]byte, 40+8+len(qAAAA))
	pktAAAA[0] = 0x60
	binary.BigEndian.PutUint16(pktAAAA[4:6], uint16(8+len(qAAAA)))
	pktAAAA[6] = 17 // UDP
	pktAAAA[7] = 64
	copy(pktAAAA[8:24], srcIP)
	copy(pktAAAA[24:40], dstIP)
	binary.BigEndian.PutUint16(pktAAAA[40:42], srcPort)
	binary.BigEndian.PutUint16(pktAAAA[42:44], dstPort)
	binary.BigEndian.PutUint16(pktAAAA[44:46], uint16(8+len(qAAAA)))
	copy(pktAAAA[48:], qAAAA)

	var addrAAAA Address
	addrAAAA.SetOutbound(true)
	addrAAAA.SetIPv6(true)

	actAAAA, replyAAAA, errAAAA := h.ProcessPacket(pktAAAA, &addrAAAA)
	if errAAAA != nil {
		t.Fatalf("ProcessPacket IPv6 DNS Type AAAA: %v", errAAAA)
	}
	if actAAAA != ActionDropDNSIPv6 {
		t.Fatalf("expected ActionDropDNSIPv6, got %v", actAAAA)
	}
	if replyAAAA == nil {
		t.Fatalf("expected synthesized IPv6 NODATA response packet, got nil")
	}

	parsedAAAA, pErrAAAA := dnsdoh.ParseResponse(replyAAAA[48:], 0x5678, "discord.com", dnsdoh.TypeAAAA)
	if pErrAAAA != nil && !errors.Is(pErrAAAA, dnsdoh.ErrNoData) {
		t.Fatalf("ParseResponse Type AAAA: %v", pErrAAAA)
	}
	if len(parsedAAAA.IPs) != 0 {
		t.Errorf("expected 0 IPs for clean NODATA, got %v", parsedAAAA.IPs)
	}

	// 3. Fallback when DNSResolver is nil -> ActionDropDNSIPv6 with nil packet
	hNoResolver := NewHarness(DefaultHarnessConfig())
	hNoResolver.cfg.InterceptDNS = true
	hNoResolver.cfg.DNSResolver = nil
	defer hNoResolver.Close()

	var addrNoRes Address
	addrNoRes.SetOutbound(true)
	addrNoRes.SetIPv6(true)

	actNoRes, replyNoRes, errNoRes := hNoResolver.ProcessPacket(pktA, &addrNoRes)
	if errNoRes != nil {
		t.Fatalf("ProcessPacket without resolver: %v", errNoRes)
	}
	if actNoRes != ActionDropDNSIPv6 {
		t.Fatalf("expected ActionDropDNSIPv6, got %v", actNoRes)
	}
	if replyNoRes != nil {
		t.Errorf("expected nil reply when DNSResolver == nil, got %d bytes", len(replyNoRes))
	}

	// 4. Inbound IPv6 packet is passed through
	var addrInbound Address
	addrInbound.SetOutbound(false)
	addrInbound.SetIPv6(true)

	actInbound, replyInbound, errInbound := h.ProcessPacket(pktA, &addrInbound)
	if errInbound != nil {
		t.Fatalf("ProcessPacket inbound IPv6: %v", errInbound)
	}
	if actInbound != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath for inbound IPv6, got %v", actInbound)
	}
	if !bytes.Equal(replyInbound, pktA) {
		t.Errorf("inbound IPv6 packet modified")
	}
}

func TestSinkholeGuardAndTCP53Blocking(t *testing.T) {
	var flushCalls atomic.Int32

	cfg := DefaultHarnessConfig()
	cfg.FlushDNSFunc = func() ([]byte, error) {
		flushCalls.Add(1)
		return []byte("Successfully flushed the DNS Resolver Cache."), nil
	}
	h := NewHarness(cfg)
	defer h.Close()

	// 1. Outbound packet to Turk Telekom sinkhole IP 195.175.254.2
	sinkholeIP := [4]byte{195, 175, 254, 2}
	tcpCfgSinkhole := packetlab.DefaultPacketConfig()
	tcpCfgSinkhole.DstIP = sinkholeIP
	tcpCfgSinkhole.DstPort = 443
	pktSinkhole, err := packetlab.BuildIPv4TCPPacket(tcpCfgSinkhole)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket sinkhole: %v", err)
	}

	var addrOutbound Address
	addrOutbound.SetOutbound(true)

	act1, reply1, err1 := h.ProcessPacket(pktSinkhole, &addrOutbound)
	if err1 != nil {
		t.Fatalf("ProcessPacket sinkhole: %v", err1)
	}
	if act1 != ActionDropSinkhole {
		t.Fatalf("expected ActionDropSinkhole, got %v", act1)
	}
	if reply1 != nil {
		t.Errorf("expected nil reply for dropped sinkhole packet, got %d bytes", len(reply1))
	}
	if h.stats.SinkholeBlocks.Load() != 1 {
		t.Errorf("expected SinkholeBlocks = 1, got %d", h.stats.SinkholeBlocks.Load())
	}

	// Wait briefly for asynchronous flush goroutine
	for i := 0; i < 50; i++ {
		if flushCalls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if flushCalls.Load() != 1 {
		t.Errorf("expected FlushDNSFunc called 1 time, got %d", flushCalls.Load())
	}
	if h.stats.DNSFlushesTriggered.Load() != 1 {
		t.Errorf("expected DNSFlushesTriggered = 1, got %d", h.stats.DNSFlushesTriggered.Load())
	}

	// 2. Immediate second outbound packet to sinkhole should be blocked, but flush rate-limited
	act2, _, _ := h.ProcessPacket(pktSinkhole, &addrOutbound)
	if act2 != ActionDropSinkhole {
		t.Fatalf("expected ActionDropSinkhole on 2nd packet, got %v", act2)
	}
	if h.stats.SinkholeBlocks.Load() != 2 {
		t.Errorf("expected SinkholeBlocks = 2, got %d", h.stats.SinkholeBlocks.Load())
	}
	if flushCalls.Load() != 1 {
		t.Errorf("expected FlushDNSFunc still 1 (rate-limited), got %d", flushCalls.Load())
	}

	// 3. Inbound packet from 195.175.254.2 is passed through
	var addrInbound Address
	addrInbound.SetOutbound(false)
	actInbound, replyInbound, errInbound := h.ProcessPacket(pktSinkhole, &addrInbound)
	if errInbound != nil {
		t.Fatalf("ProcessPacket inbound sinkhole: %v", errInbound)
	}
	if actInbound != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath for inbound sinkhole, got %v", actInbound)
	}
	if !bytes.Equal(replyInbound, pktSinkhole) {
		t.Errorf("inbound sinkhole packet modified")
	}

	// 4. Outbound TCP port 53 packet dropped (ActionDropTCP53) for non-bootstrap IP
	tcp53Cfg := packetlab.DefaultPacketConfig()
	tcp53Cfg.DstIP = [4]byte{195, 175, 39, 39} // ISP DNS resolver
	tcp53Cfg.DstPort = 53
	pktTCP53, err := packetlab.BuildIPv4TCPPacket(tcp53Cfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket TCP-53: %v", err)
	}

	var addrTCP53 Address
	addrTCP53.SetOutbound(true)

	actTCP53, replyTCP53, errTCP53 := h.ProcessPacket(pktTCP53, &addrTCP53)
	if errTCP53 != nil {
		t.Fatalf("ProcessPacket TCP-53: %v", errTCP53)
	}
	if actTCP53 != ActionDropTCP53 {
		t.Fatalf("expected ActionDropTCP53, got %v", actTCP53)
	}
	if replyTCP53 != nil {
		t.Errorf("expected nil reply for dropped TCP-53 packet, got %d bytes", len(replyTCP53))
	}

	// 5. Outbound TCP port 53 packet to DoH bootstrap IP (e.g. 8.8.8.8 / 1.1.1.1) is also dropped (ActionDropTCP53)
	// so TCP Port 53 DNS queries to 8.8.8.8 / 1.1.1.1 cannot escape to ISP DPI and return 195.175.254.2.
	for _, dip := range [][4]byte{{8, 8, 8, 8}, {1, 1, 1, 1}} {
		tcp53BootstrapCfg := packetlab.DefaultPacketConfig()
		tcp53BootstrapCfg.DstIP = dip
		tcp53BootstrapCfg.DstPort = 53
		pktBootstrap, err := packetlab.BuildIPv4TCPPacket(tcp53BootstrapCfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket bootstrap %v: %v", dip, err)
		}

		var addrBootstrap Address
		addrBootstrap.SetOutbound(true)

		actBootstrap, replyBootstrap, errBootstrap := h.ProcessPacket(pktBootstrap, &addrBootstrap)
		if errBootstrap != nil {
			t.Fatalf("ProcessPacket bootstrap TCP-53 %v: %v", dip, errBootstrap)
		}
		if actBootstrap != ActionDropTCP53 {
			t.Fatalf("expected ActionDropTCP53 for bootstrap TCP-53 to %v, got %v", dip, actBootstrap)
		}
		if replyBootstrap != nil {
			t.Errorf("expected nil reply for dropped bootstrap TCP-53 packet to %v, got %d bytes", dip, len(replyBootstrap))
		}
	}

	// 6. Inbound TCP port 53 packet passed through
	addrTCP53.SetOutbound(false)
	actTCP53In, replyTCP53In, errTCP53In := h.ProcessPacket(pktTCP53, &addrTCP53)
	if errTCP53In != nil {
		t.Fatalf("ProcessPacket inbound TCP-53: %v", errTCP53In)
	}
	if actTCP53In != ActionPassFastPath {
		t.Fatalf("expected ActionPassFastPath for inbound TCP-53, got %v", actTCP53In)
	}
	if !bytes.Equal(replyTCP53In, pktTCP53) {
		t.Errorf("inbound TCP-53 packet modified")
	}
}

func TestDoHBootstrapIPFastPathAndSinkholeRSTACK(t *testing.T) {
	// 1. Verify FastPathInspect returns ActionPassFastPath for all 4 DoH bootstrap IPs on TCP 443
	bootstrapIPs := [][4]byte{
		{1, 1, 1, 1},
		{1, 0, 0, 1},
		{8, 8, 8, 8},
		{8, 8, 4, 4},
	}
	for _, dip := range bootstrapIPs {
		cfg := packetlab.DefaultPacketConfig()
		cfg.DstIP = dip
		cfg.DstPort = 443
		cfg.Payload = packetlab.BuildDummyClientHello("cloudflare-dns.com")
		pkt, err := packetlab.BuildIPv4TCPPacket(cfg)
		if err != nil {
			t.Fatalf("BuildIPv4TCPPacket for %v: %v", dip, err)
		}
		act, _ := FastPathInspect(pkt)
		if act != ActionPassFastPath {
			t.Errorf("FastPathInspect on TCP 443 to %v = %v, want ActionPassFastPath", dip, act)
		}
	}

	// 2. Verify HandlePacket on outbound TCP packet to 195.175.254.2 synthesizes inbound TCP RST+ACK
	mock := &MockPacketSender{}
	hCfg := DefaultHarnessConfig()
	hCfg.Sender = mock
	hCfg.FlushDNSFunc = func() ([]byte, error) {
		return []byte("flushed"), nil
	}
	h := NewHarness(hCfg)
	defer h.Close()

	srcIP := [4]byte{192, 168, 1, 100}
	sinkholeIP := [4]byte{195, 175, 254, 2}
	origSeq := uint32(777000)
	origAck := uint32(888000)
	payload := packetlab.BuildDummyClientHello("discord.com")

	tcpCfg := packetlab.DefaultPacketConfig()
	tcpCfg.SrcIP = srcIP
	tcpCfg.DstIP = sinkholeIP
	tcpCfg.SrcPort = 51234
	tcpCfg.DstPort = 443
	tcpCfg.SeqNum = origSeq
	tcpCfg.AckNum = origAck
	tcpCfg.Payload = payload
	pktSinkhole, err := packetlab.BuildIPv4TCPPacket(tcpCfg)
	if err != nil {
		t.Fatalf("BuildIPv4TCPPacket sinkhole: %v", err)
	}

	var addr Address
	addr.SetOutbound(true)

	if err := h.HandlePacket(pktSinkhole, &addr, mock); err != nil {
		t.Fatalf("HandlePacket sinkhole: %v", err)
	}

	calls := mock.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 synthesized inbound RST+ACK packet, got %d", len(calls))
	}

	rstCall := calls[0]
	if rstCall.Addr.Outbound() {
		t.Errorf("expected RST+ACK Addr.Outbound() = false")
	}
	if !rstCall.Addr.IPChecksum() || !rstCall.Addr.TCPChecksum() {
		t.Errorf("expected RST+ACK Addr IPChecksum and TCPChecksum = true")
	}

	rstPkt := rstCall.Packet
	if !bytes.Equal(rstPkt[12:16], sinkholeIP[:]) {
		t.Errorf("expected RST+ACK SrcIP = 195.175.254.2, got %v", rstPkt[12:16])
	}
	if !bytes.Equal(rstPkt[16:20], srcIP[:]) {
		t.Errorf("expected RST+ACK DstIP = %v, got %v", srcIP, rstPkt[16:20])
	}
	rstSrcPort := binary.BigEndian.Uint16(rstPkt[20:22])
	rstDstPort := binary.BigEndian.Uint16(rstPkt[22:24])
	if rstSrcPort != 443 || rstDstPort != 51234 {
		t.Errorf("expected RST+ACK ports 443 -> 51234, got %d -> %d", rstSrcPort, rstDstPort)
	}
	rstSeq := binary.BigEndian.Uint32(rstPkt[24:28])
	rstAck := binary.BigEndian.Uint32(rstPkt[28:32])
	if rstSeq != origAck {
		t.Errorf("expected RST+ACK SeqNum = %d, got %d", origAck, rstSeq)
	}
	if rstAck != origSeq+uint32(len(payload)) {
		t.Errorf("expected RST+ACK AckNum = %d, got %d", origSeq+uint32(len(payload)), rstAck)
	}
	rstFlags := rstPkt[33]
	wantFlags := uint8(packetlab.TCPFlagRST | packetlab.TCPFlagACK)
	if rstFlags != wantFlags {
		t.Errorf("expected RST+ACK TCPFlags = 0x%02x, got 0x%02x", wantFlags, rstFlags)
	}
}

func TestWinDivertFilterCompileAndEvalBootstrapAndSinkhole(t *testing.T) {
	dll, err := syscall.LoadDLL(filepath.Join("..", "..", "WinDivert.dll"))
	if err != nil {
		t.Skipf("WinDivert.dll not available for eval test: %v", err)
	}
	defer dll.Release()

	compileFilterProc, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatalf("FindProc CompileFilter: %v", err)
	}
	evalFilterProc, err := dll.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatalf("FindProc EvalFilter: %v", err)
	}

	for _, filter := range []string{FilterOutboundProduction, FilterOutboundWithDNS} {
		filterPtr, _ := syscall.BytePtrFromString(filter)
		var errStrPtr uintptr
		var errPos uint32
		rComp, _, _ := compileFilterProc.Call(
			uintptr(unsafe.Pointer(filterPtr)),
			uintptr(LayerNetwork),
			0,
			0,
			uintptr(unsafe.Pointer(&errStrPtr)),
			uintptr(unsafe.Pointer(&errPos)),
		)
		if rComp == 0 {
			t.Fatalf("WinDivertHelperCompileFilter failed on %q at pos %d", filter, errPos)
		}

		var addr Address
		addr.SetOutbound(true)
		addr.SetLoopback(false)
		addr.SetImpostor(false)
		addr.SetIPv6(false)

		// 1. DoH bootstrap IPs on TCP 443 must evaluate to FALSE (excluded from WinDivert capture)
		for _, dip := range [][4]byte{{1, 1, 1, 1}, {1, 0, 0, 1}, {8, 8, 8, 8}, {8, 8, 4, 4}} {
			cfg := packetlab.DefaultPacketConfig()
			cfg.SrcIP = [4]byte{192, 168, 1, 100}
			cfg.DstIP = dip
			cfg.DstPort = 443
			cfg.Payload = packetlab.BuildDummyClientHello("cloudflare-dns.com")
			pkt, _ := packetlab.BuildIPv4TCPPacket(cfg)
			rEval, _, _ := evalFilterProc.Call(
				uintptr(unsafe.Pointer(filterPtr)),
				uintptr(unsafe.Pointer(&pkt[0])),
				uintptr(len(pkt)),
				uintptr(unsafe.Pointer(&addr)),
			)
			if rEval != 0 {
				t.Errorf("filter %q unexpectedly matched DoH bootstrap IP %v on TCP 443", filter, dip)
			}
		}

		// 2. Sinkhole IP 195.175.254.2 TCP SYN (empty payload) and data must evaluate to TRUE
		synCfg := packetlab.DefaultPacketConfig()
		synCfg.SrcIP = [4]byte{192, 168, 1, 100}
		synCfg.DstIP = [4]byte{195, 175, 254, 2}
		synCfg.DstPort = 443
		synCfg.TCPFlags = packetlab.TCPFlagSYN
		synCfg.Payload = nil
		synPkt, _ := packetlab.BuildIPv4TCPPacket(synCfg)
		rSyn, _, _ := evalFilterProc.Call(
			uintptr(unsafe.Pointer(filterPtr)),
			uintptr(unsafe.Pointer(&synPkt[0])),
			uintptr(len(synPkt)),
			uintptr(unsafe.Pointer(&addr)),
		)
		if rSyn == 0 {
			t.Errorf("filter %q failed to match TCP SYN to sinkhole 195.175.254.2", filter)
		}

		// 3. FilterOutboundWithDNS must capture TCP Port 53 even to 8.8.8.8 / 1.1.1.1
		if filter == FilterOutboundWithDNS {
			for _, dip := range [][4]byte{{1, 1, 1, 1}, {8, 8, 8, 8}} {
				tcp53Cfg := packetlab.DefaultPacketConfig()
				tcp53Cfg.SrcIP = [4]byte{192, 168, 1, 100}
				tcp53Cfg.DstIP = dip
				tcp53Cfg.DstPort = 53
				tcp53Cfg.TCPFlags = packetlab.TCPFlagSYN
				tcp53Pkt, _ := packetlab.BuildIPv4TCPPacket(tcp53Cfg)
				rTCP53, _, _ := evalFilterProc.Call(
					uintptr(unsafe.Pointer(filterPtr)),
					uintptr(unsafe.Pointer(&tcp53Pkt[0])),
					uintptr(len(tcp53Pkt)),
					uintptr(unsafe.Pointer(&addr)),
				)
				if rTCP53 == 0 {
					t.Errorf("FilterOutboundWithDNS failed to match TCP Port 53 to %v", dip)
				}
			}
		}
	}

	// 3. Verify batch scripts contain no echo lines with parentheses that break cmd.exe if/for blocks
	for _, relPath := range []string{"../../start-bypass.bat", "../../launch-discord.bat", "../../stop-and-recover.bat"} {
		data, err := os.ReadFile(relPath)
		if err != nil {
			t.Fatalf("read %s: %v", relPath, err)
		}
		lines := strings.Split(string(data), "\n")
		for idx, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmed), "echo ") {
				if strings.Contains(trimmed, "(") || strings.Contains(trimmed, ")") {
					t.Errorf("%s line %d contains parenthesis inside echo statement: %s", relPath, idx+1, trimmed)
				}
			}
		}
	}
}

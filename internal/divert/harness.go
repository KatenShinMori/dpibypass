//go:build windows && amd64

package divert

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/dnsdoh"
	"dpibypass/internal/packetlab"
	"dpibypass/internal/strategy"
	"dpibypass/internal/tlsparse"
)

// FastPathAction defines the handling classification for an intercepted packet.
type FastPathAction int

const (
	// ActionPassFastPath indicates the packet does not match target handshake signatures
	// (e.g. bulk TCP data without 0x16 prefix, non-HTTP port 80, or non-target UDP)
	// and should be immediately re-injected via WinDivertSend with zero allocation.
	ActionPassFastPath FastPathAction = iota

	// ActionDropQUIC indicates the packet is outbound UDP/443 and must be dropped
	// to force client/browser fallback to HTTP/2 over TCP.
	ActionDropQUIC

	// ActionInspectCandidate indicates the packet is a target TLS ClientHello (port 443 + 0x16 prefix)
	// or HTTP request (port 80 + HTTP method prefix) destined for desync processing.
	ActionInspectCandidate

	// ActionInterceptDNS indicates the packet is an outbound IPv4 UDP/53 DNS query
	// targeted for RFC 1035 wire parsing and DoH resolution.
	ActionInterceptDNS

	// ActionDropDNSIPv6 indicates the packet is an outbound IPv6 UDP/53 DNS query.
	ActionDropDNSIPv6

	// ActionDropIPv6TCP indicates the packet is outbound IPv6 TCP port 80/443
	// dropped to prevent ISP blocking leaks and force immediate Happy Eyeballs fallback to IPv4.
	ActionDropIPv6TCP

	// ActionDropTCP53 indicates the packet is outbound TCP port 53
	// dropped to prevent unencrypted DNS fallback leaks to ISP middleboxes.
	ActionDropTCP53

	// ActionDropSinkhole indicates the packet is outbound IPv4 to the ISP sinkhole IP (195.175.254.2)
	// dropped to trigger client re-resolution.
	ActionDropSinkhole
)

func (a FastPathAction) String() string {
	switch a {
	case ActionPassFastPath:
		return "pass_fast_path"
	case ActionDropQUIC:
		return "drop_quic"
	case ActionInspectCandidate:
		return "inspect_candidate"
	case ActionInterceptDNS:
		return "intercept_dns"
	case ActionDropDNSIPv6:
		return "drop_dns_ipv6"
	case ActionDropIPv6TCP:
		return "drop_ipv6_tcp"
	case ActionDropTCP53:
		return "drop_tcp_53"
	case ActionDropSinkhole:
		return "drop_sinkhole"
	default:
		return fmt.Sprintf("action_%d", int(a))
	}
}

// PacketSender abstracts raw packet reinjection to the network stack.
type PacketSender interface {
	Send(packet []byte, addr *Address) (int, error)
}

// PacketSenderFunc adapts a function to the PacketSender interface.
type PacketSenderFunc func(packet []byte, addr *Address) (int, error)

func (f PacketSenderFunc) Send(packet []byte, addr *Address) (int, error) {
	return f(packet, addr)
}

// DomainMatcher abstracts matching candidate domains against configured profiles.
type DomainMatcher interface {
	Match(domain string) (profile string, matched bool)
}

// PacketHandler allows injecting strategy desync transformers for candidate packets.
type PacketHandler interface {
	HandleCandidate(packet []byte, addr *Address, payloadOffset int) ([]byte, error)
}

// DNSQueryResolver defines the domain resolution interface for transparent UDP-53 DNS interception.
type DNSQueryResolver interface {
	ResolveQueryType(ctx context.Context, domain string, qtype uint16) (ips []net.IP, ttl time.Duration, isNoData bool, err error)
}

// HarnessConfig specifies operational parameters for the WinDivert packet engine.
type HarnessConfig struct {
	Filter           string
	Priority         int16
	QueueLen         uint32
	QueueTime        uint32
	QueueSize        uint32
	DropQUIC         bool
	Handler          PacketHandler
	Sender           PacketSender
	SplitOffset      string
	InterPacketDelay time.Duration
	TargetDomains    []string
	DomainMatcher    DomainMatcher
	DefaultProfile   string

	// Milestone 2.3 Fake Packet & Middlebox Poisoning settings:
	FakePacketMode  string        // Evasion mode: "ttl", "wrong-chksum", "both" (or "ttl+wrong-chksum")
	FakeTTL         uint8         // Configurable low hop count (default 5, range 2-16)
	FakeSNI         string        // Benign dummy SNI (default "www.example.com")
	FakePacketDelay time.Duration // Optional delay between fake packet and real packet (default 0)

	// Milestone 2.5 Port 80 Wire Engine:
	DesyncHTTP bool // When true, enables wire-level fake packet injection and out-of-order splitting for port 80 HTTP requests

	// Milestone 2.6 Transparent UDP-53 DNS Interception:
	InterceptDNS bool
	DNSResolver  DNSQueryResolver
	DoHResolver  DNSQueryResolver

	// Milestone 2.7 Adaptive Retransmission & Auto-Learner settings:
	AutoLearn         bool
	AutoLearnPath     string
	AutoLearner       *AutoLearner
	ExcludedHostnames []string
	DoHEndpoints      []string
	ExplicitOverrides bool

	// Milestone 2.8 Sinkhole & DNS flushing
	FlushDNSFunc func() ([]byte, error)

	// Logger for WinDivert kernel operations
	Logger *slog.Logger
}

const (
	// DefaultFakeTTL is the default low hop count for Low-TTL fake packet evasion.
	DefaultFakeTTL = 4
	// DefaultFakeSNI is the default benign hostname for fake TLS ClientHello payloads.
	DefaultFakeSNI = "www.example.com"
	// SinkholeIP is the Turk Telekom / BTK DNS poison sinkhole IP address.
	SinkholeIP = "195.175.254.2"
)

// DefaultHarnessConfig returns safe default settings for the production harness.
func DefaultHarnessConfig() HarnessConfig {
	return HarnessConfig{
		Filter:        FilterOutboundProduction,
		Priority:      0,
		QueueLen:      ParamQueueLengthDefault, // 4096
		QueueTime:     ParamQueueTimeDefault,   // 2000 ms
		QueueSize:     ParamQueueSizeDefault,   // 4 MB
		DropQUIC:      true,
		SplitOffset:   "sni-mid",
		AutoLearn:     true,
		AutoLearnPath: "autolearn.json",
	}
}

// HarnessStats records real-time packet processing metrics.
type HarnessStats struct {
	PacketsRecv                atomic.Uint64
	PacketsSent                atomic.Uint64
	QUICDropped                atomic.Uint64
	TCPFastPath                atomic.Uint64
	TCPCandidate               atomic.Uint64
	CandidateHandshakes        atomic.Uint64
	PacketsSplit               atomic.Uint64
	OutOfOrderSegmentsInjected atomic.Uint64
	PassThroughFallbacks       atomic.Uint64
	SendErrors                 atomic.Uint64

	// Milestone 2.3 Fake Packet & Middlebox Poisoning metrics:
	FakePacketsInjected  atomic.Uint64
	FakeTTLCount         atomic.Uint64
	FakeBadChecksumCount atomic.Uint64
	FakeSendErrors       atomic.Uint64

	// Milestone 2.6 Transparent UDP-53 DNS Interception metrics:
	DNSQueriesIntercepted atomic.Uint64
	DNSQueriesResolvedDoH atomic.Uint64
	DNSFallbacks          atomic.Uint64

	// Milestone 2.7 Adaptive Retransmission & Auto-Learner metrics:
	RetransmissionsDetected atomic.Uint64
	StrategyEscalations     atomic.Uint64
	DomainsAutoLearned      atomic.Uint64

	// Milestone 2.8 Sinkhole Guard & Packet 2 Desync metrics:
	SinkholeBlocks      atomic.Uint64
	DNSFlushesTriggered atomic.Uint64
	Packet2Desynced     atomic.Uint64
}

type flowTuple struct {
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
}

type pqEntry struct {
	nextSeq   uint32
	expiresAt time.Time
}

type pqPacketTracker struct {
	mu      sync.Mutex
	entries map[flowTuple]pqEntry
}

func newPQPacketTracker() *pqPacketTracker {
	return &pqPacketTracker{
		entries: make(map[flowTuple]pqEntry),
	}
}

func (t *pqPacketTracker) Record(srcIP, dstIP [4]byte, srcPort, dstPort uint16, nextSeq uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if len(t.entries) >= 512 {
		for k, v := range t.entries {
			if now.After(v.expiresAt) {
				delete(t.entries, k)
			}
		}
	}
	if len(t.entries) >= 1024 {
		for k := range t.entries {
			delete(t.entries, k)
			break
		}
	}
	tuple := flowTuple{
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
	}
	t.entries[tuple] = pqEntry{
		nextSeq:   nextSeq,
		expiresAt: now.Add(10 * time.Second),
	}
}

func (t *pqPacketTracker) MatchAndRemove(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seqNum uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	tuple := flowTuple{
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
	}
	entry, ok := t.entries[tuple]
	if !ok {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		delete(t.entries, tuple)
		return false
	}
	if entry.nextSeq != seqNum {
		return false
	}
	delete(t.entries, tuple)
	return true
}

// Harness coordinates the elevated WinDivert packet loop, zero-allocation fast path,
// QUIC suppression, and clean lifecycle management.
type Harness struct {
	cfg               HarnessConfig
	stats             HarnessStats
	handle            Handle
	mu                sync.Mutex
	closed            atomic.Bool
	paused            atomic.Bool
	pauseMu           sync.Mutex
	resumeCh          chan struct{}
	dnsSem            chan struct{}
	autoLearner       *AutoLearner
	excludedHostnames []string
	pqTracker         *pqPacketTracker
	lastDNSFlush      atomic.Int64
	sendMu            sync.Mutex
}

// NewHarness creates and validates a new Harness instance.
func NewHarness(cfg HarnessConfig) *Harness {
	if cfg.DNSResolver == nil && cfg.DoHResolver != nil {
		cfg.DNSResolver = cfg.DoHResolver
	}
	if cfg.DoHResolver == nil && cfg.DNSResolver != nil {
		cfg.DoHResolver = cfg.DNSResolver
	}
	if cfg.InterceptDNS && cfg.DNSResolver == nil {
		if defRes, err := dnsdoh.NewResolver(config.DefaultConfig().DoH, cfg.Logger); err == nil {
			cfg.DNSResolver = defRes
			cfg.DoHResolver = defRes
		}
	}
	if cfg.InterceptDNS && (cfg.Filter == "" || cfg.Filter == FilterOutboundProduction) {
		cfg.Filter = FilterOutboundWithDNS
	} else if !cfg.InterceptDNS && cfg.Filter == "" {
		cfg.Filter = FilterOutboundProduction
	}
	if cfg.QueueLen == 0 {
		cfg.QueueLen = ParamQueueLengthDefault
	}
	if cfg.QueueTime == 0 {
		cfg.QueueTime = ParamQueueTimeDefault
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = ParamQueueSizeDefault
	}
	if cfg.SplitOffset == "" {
		cfg.SplitOffset = "sni-mid"
	}

	defaultExcluded := []string{
		"cloudflare-dns.com",
		"dns.google",
		"one.one.one.one",
	}
	excludedMap := make(map[string]struct{})
	for _, ex := range defaultExcluded {
		if d := cleanHost(ex); d != "" {
			excludedMap[d] = struct{}{}
		}
	}
	for _, ex := range cfg.ExcludedHostnames {
		if d := cleanHost(ex); d != "" {
			excludedMap[d] = struct{}{}
		}
	}
	for _, ep := range cfg.DoHEndpoints {
		if d := cleanHost(ep); d != "" {
			excludedMap[d] = struct{}{}
		}
	}
	excluded := make([]string, 0, len(excludedMap))
	for d := range excludedMap {
		excluded = append(excluded, d)
	}

	al := cfg.AutoLearner
	if al == nil {
		persistPath := cfg.AutoLearnPath
		if persistPath == "" {
			persistPath = "autolearn.json"
		}
		al = NewAutoLearner(persistPath, cfg.AutoLearn)
	}

	h := &Harness{
		cfg:               cfg,
		handle:            InvalidHandle,
		resumeCh:          make(chan struct{}, 1),
		dnsSem:            make(chan struct{}, 64),
		autoLearner:       al,
		excludedHostnames: excluded,
		pqTracker:         newPQPacketTracker(),
	}
	if al != nil {
		h.stats.DomainsAutoLearned.Store(uint64(al.DomainCount()))
	}
	return h
}

// Stats returns a copy of current packet processing counters.
func (h *Harness) Stats() (recv, sent, quicDrop, fastPath, candidate uint64) {
	return h.stats.PacketsRecv.Load(),
		h.stats.PacketsSent.Load(),
		h.stats.QUICDropped.Load(),
		h.stats.TCPFastPath.Load(),
		h.stats.TCPCandidate.Load()
}

// ExtendedStats returns detailed metrics for Phase 2 out-of-order fragmentation.
func (h *Harness) ExtendedStats() (handshakes, split, injected, fallbacks, sendErrors uint64) {
	return h.stats.CandidateHandshakes.Load(),
		h.stats.PacketsSplit.Load(),
		h.stats.OutOfOrderSegmentsInjected.Load(),
		h.stats.PassThroughFallbacks.Load(),
		h.stats.SendErrors.Load()
}

// FakeStats returns detailed metrics for Milestone 2.3 fake packet injection.
func (h *Harness) FakeStats() (injected, ttlCount, badChecksumCount, sendErrors uint64) {
	return h.stats.FakePacketsInjected.Load(),
		h.stats.FakeTTLCount.Load(),
		h.stats.FakeBadChecksumCount.Load(),
		h.stats.FakeSendErrors.Load()
}

// DNSStats returns atomic counters for Milestone 2.6 transparent DNS interception.
func (h *Harness) DNSStats() (intercepted, resolvedDoH, fallbacks uint64) {
	return h.stats.DNSQueriesIntercepted.Load(),
		h.stats.DNSQueriesResolvedDoH.Load(),
		h.stats.DNSFallbacks.Load()
}

// AutoLearnStats returns atomic counters for Milestone 2.7 adaptive retransmission learning.
func (h *Harness) AutoLearnStats() (retransmissions, escalations, domainsLearned uint64) {
	return h.stats.RetransmissionsDetected.Load(),
		h.stats.StrategyEscalations.Load(),
		h.stats.DomainsAutoLearned.Load()
}

// SinkholeStats returns atomic counters for Milestone 2.8 sinkhole guard and Packet 2 desync.
func (h *Harness) SinkholeStats() (sinkholeBlocks, dnsFlushes, packet2Desynced uint64) {
	return h.stats.SinkholeBlocks.Load(),
		h.stats.DNSFlushesTriggered.Load(),
		h.stats.Packet2Desynced.Load()
}

// ListLearnedDomains returns all domains with learned evasion strategies.
func (h *Harness) ListLearnedDomains() []LearnedDomain {
	if h.autoLearner == nil {
		return nil
	}
	return h.autoLearner.ListLearnedDomains()
}

// GetAutoLearner returns the active AutoLearner instance.
func (h *Harness) GetAutoLearner() *AutoLearner {
	return h.autoLearner
}

// Handle returns the current WinDivert handle.
func (h *Harness) Handle() Handle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handle
}

// FastPathInspect evaluates an intercepted packet with zero heap allocations.
// It inspects IPv4/IPv6 and TCP/UDP headers using direct byte indexing:
//   - Outbound UDP port 443 returns ActionDropQUIC.
//   - Outbound TCP port 443 with payload starting with 0x16 returns ActionInspectCandidate.
//   - Outbound TCP port 80 with payload starting with an HTTP method returns ActionInspectCandidate.
//   - All other packets return ActionPassFastPath.
func FastPathInspect(packet []byte) (FastPathAction, int) {
	if len(packet) < 20 {
		return ActionPassFastPath, 0
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		ihl := int(packet[0]&0x0F) * 4
		if ihl < 20 || len(packet) < ihl+8 {
			return ActionPassFastPath, 0
		}

		// Non-first IPv4 fragments do not contain transport headers
		if binary.BigEndian.Uint16(packet[6:8])&0x1FFF != 0 {
			return ActionPassFastPath, 0
		}

		// Fix 3: Sinkhole Guard for 195.175.254.2 (Türk Telekom BTK sinkhole IP)
		if packet[16] == 195 && packet[17] == 175 && packet[18] == 254 && packet[19] == 2 && packet[9] == 6 {
			return ActionDropSinkhole, 0
		}

		proto := packet[9]
		switch proto {
		case 17: // UDP
			dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
			if dstPort == 443 {
				return ActionDropQUIC, ihl + 8
			}
			if dstPort == 53 {
				return ActionInterceptDNS, ihl + 8
			}
			return ActionPassFastPath, 0

		case 6: // TCP
			if len(packet) < ihl+20 {
				return ActionPassFastPath, 0
			}
			dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
			if dstPort == 53 {
				return ActionDropTCP53, ihl + 20
			}
			if dstPort == 443 && isDoHBootstrapIPBytes(packet[16], packet[17], packet[18], packet[19]) {
				return ActionPassFastPath, 0
			}
			if dstPort != 443 && dstPort != 80 {
				return ActionPassFastPath, 0
			}

			tcpDataOffset := int(packet[ihl+12]>>4) * 4
			if tcpDataOffset < 20 {
				return ActionPassFastPath, 0
			}

			payloadOffset := ihl + tcpDataOffset
			if payloadOffset >= len(packet) {
				return ActionPassFastPath, 0 // No payload (e.g. pure ACK)
			}

			payload := packet[payloadOffset:]
			if len(payload) == 0 {
				return ActionPassFastPath, 0
			}

			if dstPort == 443 {
				// Fast path: TLS Handshake starts strictly with 0x16 (ContentType 22).
				// Bulk uploads, Application Data (0x17), Alerts (0x15), etc., pass immediately.
				if payload[0] == 0x16 {
					return ActionInspectCandidate, payloadOffset
				}
				return ActionPassFastPath, payloadOffset
			}

			if dstPort == 80 {
				if isHTTPMethodPrefix(payload) {
					return ActionInspectCandidate, payloadOffset
				}
				return ActionPassFastPath, payloadOffset
			}

			return ActionPassFastPath, 0

		default:
			return ActionPassFastPath, 0
		}

	case 6:
		// IPv6 fixed header is 40 bytes
		if len(packet) < 40+8 {
			return ActionPassFastPath, 0
		}
		nextHeader := packet[6]
		headerLen := 40

		// Walk standard IPv6 extension headers (RFC 8200) to find the transport layer
		for headerLen < len(packet) {
			if nextHeader == 17 || nextHeader == 6 {
				break
			}
			// Hop-by-Hop (0), Routing (43), Destination Options (60)
			if nextHeader == 0 || nextHeader == 43 || nextHeader == 60 {
				if headerLen+2 > len(packet) {
					return ActionPassFastPath, 0
				}
				extLen := int(packet[headerLen+1]+1) * 8
				if headerLen+extLen > len(packet) {
					return ActionPassFastPath, 0
				}
				nextHeader = packet[headerLen]
				headerLen += extLen
				continue
			}
			// Fragment Header (44): fixed 8 bytes
			if nextHeader == 44 {
				if headerLen+8 > len(packet) {
					return ActionPassFastPath, 0
				}
				// Non-first fragments cannot contain full transport headers
				fragOffset := binary.BigEndian.Uint16(packet[headerLen+2:headerLen+4]) & 0xFFF8
				if fragOffset != 0 {
					return ActionPassFastPath, 0
				}
				nextHeader = packet[headerLen]
				headerLen += 8
				continue
			}
			break
		}

		switch nextHeader {
		case 17: // UDP
			dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
			if dstPort == 443 {
				return ActionDropQUIC, headerLen + 8
			}
			if dstPort == 53 {
				return ActionDropDNSIPv6, headerLen + 8
			}
			return ActionPassFastPath, 0

		case 6: // TCP
			if len(packet) < headerLen+20 {
				return ActionPassFastPath, 0
			}
			dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
			if dstPort == 53 {
				return ActionDropTCP53, headerLen + 20
			}
			if dstPort == 443 || dstPort == 80 {
				return ActionDropIPv6TCP, headerLen + 20
			}
			return ActionPassFastPath, 0

		default:
			return ActionPassFastPath, 0
		}

	default:
		return ActionPassFastPath, 0
	}
}

// isHTTPMethodPrefix checks if payload starts with a standard ASCII HTTP request method.
// Zero heap allocations.
func isHTTPMethodPrefix(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	// "GET "
	if p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ' {
		return true
	}
	// "POST "
	if p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && len(p) > 4 && p[4] == ' ' {
		return true
	}
	// "HEAD "
	if p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D' && len(p) > 4 && p[4] == ' ' {
		return true
	}
	// "PUT "
	if p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ' {
		return true
	}
	// "OPTIONS "
	if len(p) >= 8 && p[0] == 'O' && p[1] == 'P' && p[2] == 'T' && p[3] == 'I' && p[4] == 'O' && p[5] == 'N' && p[6] == 'S' && p[7] == ' ' {
		return true
	}
	// "DELETE "
	if len(p) >= 7 && p[0] == 'D' && p[1] == 'E' && p[2] == 'L' && p[3] == 'E' && p[4] == 'T' && p[5] == 'E' && p[6] == ' ' {
		return true
	}
	// "CONNECT "
	if len(p) >= 8 && p[0] == 'C' && p[1] == 'O' && p[2] == 'N' && p[3] == 'N' && p[4] == 'E' && p[5] == 'C' && p[6] == 'T' && p[7] == ' ' {
		return true
	}
	return false
}

type liveSender struct {
	handle Handle
	mu     *sync.Mutex
}

func (s liveSender) Send(packet []byte, addr *Address) (int, error) {
	if s.mu != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	return Send(s.handle, packet, addr)
}

func (h *Harness) getSender() PacketSender {
	if h.cfg.Sender != nil {
		return h.cfg.Sender
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.handle != InvalidHandle {
		return liveSender{handle: h.handle, mu: &h.sendMu}
	}
	return nil
}

func (h *Harness) sendPacket(packet []byte, addr *Address) (int, error) {
	sender := h.getSender()
	if sender == nil {
		return 0, errors.New("no packet sender available")
	}
	return sender.Send(packet, addr)
}

func (h *Harness) isExcluded(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	for _, ex := range h.excludedHostnames {
		if matchDomainPattern(ex, d) {
			return true
		}
	}
	return false
}

func (h *Harness) matchesTarget(sni string) bool {
	sni = cleanHost(sni)
	if sni == "" {
		return false
	}
	if h.isExcluded(sni) {
		return false
	}

	if h.cfg.DomainMatcher != nil {
		profile, matched := h.cfg.DomainMatcher.Match(sni)
		if matched {
			if strings.EqualFold(profile, "none") || profile == "" {
				return false
			}
			return true
		}
		// If domain does not match any rule, defer to DefaultProfile policy
		if strings.EqualFold(h.cfg.DefaultProfile, "none") {
			return false
		}
		return true
	}

	if len(h.cfg.TargetDomains) > 0 {
		for _, pattern := range h.cfg.TargetDomains {
			if matchDomainPattern(pattern, sni) {
				return true
			}
		}
		return false
	}

	if strings.EqualFold(h.cfg.DefaultProfile, "none") {
		return false
	}

	return true
}

func (h *Harness) matchesExplicitTarget(sni string) bool {
	sni = cleanHost(sni)
	if sni == "" {
		return false
	}
	if h.isExcluded(sni) {
		return false
	}

	if h.cfg.DomainMatcher != nil {
		profile, matched := h.cfg.DomainMatcher.Match(sni)
		if matched {
			if strings.EqualFold(profile, "none") || profile == "" {
				return false
			}
			return true
		}
		return false
	}

	if len(h.cfg.TargetDomains) > 0 {
		for _, pattern := range h.cfg.TargetDomains {
			if matchDomainPattern(pattern, sni) {
				return true
			}
		}
		return false
	}

	return false
}

func cleanHost(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func matchDomainPattern(pattern, domain string) bool {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if p == "*" || p == d {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[2:]
		dotSuffix := "." + suffix
		return strings.HasSuffix(d, dotSuffix) && len(d) > len(dotSuffix)
	}
	if strings.HasSuffix(d, "."+p) {
		return true
	}
	return false
}

func isDoHBootstrapIPBytes(b0, b1, b2, b3 byte) bool {
	return (b0 == 1 && b1 == 1 && b2 == 1 && b3 == 1) ||
		(b0 == 1 && b1 == 0 && b2 == 0 && b3 == 1) ||
		(b0 == 8 && b1 == 8 && b2 == 8 && b3 == 8) ||
		(b0 == 8 && b1 == 8 && b2 == 4 && b3 == 4)
}

func isDoHBootstrapIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return isDoHBootstrapIPBytes(ip4[0], ip4[1], ip4[2], ip4[3])
}

func (h *Harness) logInfo(msg string, args ...any) {
	if h.cfg.Logger != nil {
		h.cfg.Logger.Info(msg, args...)
	} else {
		slog.Info(msg, args...)
	}
}

func (h *Harness) logError(msg string, args ...any) {
	if h.cfg.Logger != nil {
		h.cfg.Logger.Error(msg, args...)
	} else {
		slog.Error(msg, args...)
	}
}

func (h *Harness) logWarn(msg string, args ...any) {
	if h.cfg.Logger != nil {
		h.cfg.Logger.Warn(msg, args...)
	} else {
		slog.Warn(msg, args...)
	}
}

func (h *Harness) logDebug(msg string, args ...any) {
	if h.cfg.Logger != nil {
		h.cfg.Logger.Debug(msg, args...)
	} else {
		slog.Debug(msg, args...)
	}
}

func (h *Harness) triggerRateLimitedDNSFlush() {
	h.stats.DNSFlushesTriggered.Add(1)
	now := time.Now().UnixMilli()
	last := h.lastDNSFlush.Load()
	if now-last < 60000 {
		return
	}
	if h.lastDNSFlush.CompareAndSwap(last, now) {
		flushFn := h.cfg.FlushDNSFunc
		if flushFn == nil {
			flushFn = FlushDNSCache
		}
		go func() {
			_, _ = flushFn()
		}()
	}
}

func (h *Harness) handleSinkholeBlock(packet []byte, addr *Address, sender PacketSender) {
	h.stats.SinkholeBlocks.Add(1)
	h.logDebug("blocked connection to ISP sinkhole 195.175.254.2 - flushing DNS", "dst_ip", "195.175.254.2")
	h.triggerRateLimitedDNSFlush()

	if rstPkt, err := packetlab.SynthesizeInboundTCPRSTPacket(packet); err == nil {
		var rstAddr Address
		if addr != nil {
			rstAddr = *addr
		}
		rstAddr.SetOutbound(false)
		rstAddr.SetIPv6(false)
		rstAddr.SetIPChecksum(true)
		rstAddr.SetTCPChecksum(true)
		if sender != nil {
			if _, sendErr := sender.Send(rstPkt, &rstAddr); sendErr == nil {
				h.stats.PacketsSent.Add(1)
			} else {
				h.stats.SendErrors.Add(1)
			}
		}
	}
}

func (h *Harness) sendPassThrough(packet []byte, addr *Address, sender PacketSender) error {
	if sender == nil {
		h.stats.PacketsSent.Add(1)
		return nil
	}
	var sendAddr Address
	if addr != nil {
		sendAddr = *addr
	}
	_, err := sender.Send(packet, &sendAddr)
	if err != nil {
		h.stats.SendErrors.Add(1)
		return err
	}
	h.stats.PacketsSent.Add(1)
	return nil
}

func (h *Harness) fallbackPassThrough(packet []byte, addr *Address, sender PacketSender) error {
	h.stats.PassThroughFallbacks.Add(1)
	return h.sendPassThrough(packet, addr, sender)
}

// ParseFakePacketMode parses the configured fake packet evasion mode string.
// Supported modes:
//   - "ttl": Low-TTL hop count poisoning
//   - "multi-ttl" (or "ttl-auto"): Multi-hop TTL poisoning (TTL 4 + TTL 3) to defeat ECMP route shifts
//   - "wrong-chksum" (or "bad-chksum", "wrong-checksum", "bad-checksum"): RFC 793 TCP checksum corruption
//   - "both" (or any delimiter-separated combination such as "ttl+wrong-chksum", "ttl, wrong-chksum"): Both Low-TTL and bad checksum
//   - "" or "none" or "off" or "disabled": Disabled
func ParseFakePacketMode(mode string) (enabled bool, useTTL bool, useBadChecksum bool, err error) {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" || m == "none" || m == "off" || m == "disabled" {
		return false, false, false, nil
	}
	if m == "both" {
		return true, true, true, nil
	}

	parts := strings.FieldsFunc(m, func(r rune) bool {
		return r == '+' || r == ',' || r == '|'
	})
	if len(parts) == 0 {
		return false, false, false, nil
	}

	for _, part := range parts {
		token := strings.TrimSpace(part)
		switch token {
		case "":
			continue
		case "ttl", "multi-ttl", "ttl-auto":
			useTTL = true
		case "wrong-chksum", "bad-chksum", "wrong-checksum", "bad-checksum":
			useBadChecksum = true
		case "both":
			useTTL = true
			useBadChecksum = true
		default:
			return false, false, false, fmt.Errorf("unknown fake packet mode: %q", mode)
		}
	}

	enabled = useTTL || useBadChecksum
	if !enabled {
		return false, false, false, fmt.Errorf("unknown fake packet mode: %q", mode)
	}
	return enabled, useTTL, useBadChecksum, nil
}

// IsMultiTTL reports whether the mode specifies multi-hop TTL poisoning.
func IsMultiTTL(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	return strings.Contains(m, "multi-ttl") || strings.Contains(m, "ttl-auto")
}

func (h *Harness) handleCandidateFragmentation(packet []byte, addr *Address, payloadOffset int, sender PacketSender) error {
	// 1. Non-IPv4 packets: safe pass-through fallback
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	// 2. Fragmented IPv4 datagrams cannot be split: safe pass-through fallback
	fragWord := binary.BigEndian.Uint16(packet[6:8])
	if fragWord&0x2000 != 0 || fragWord&0x1FFF != 0 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+20 {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	if dstPort != 443 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	if payloadOffset <= 0 || payloadOffset >= len(packet) {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	payload := packet[payloadOffset:]
	if len(payload) < 2 || payload[0] != 0x16 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	res := tlsparse.ParseClientHello(payload, tlsparse.DefaultLimits())
	var meta *tlsparse.ClientHelloMetadata
	if res.Status == tlsparse.StatusParsed && res.Metadata != nil {
		meta = res.Metadata
	} else {
		// Fallback for Chromium Post-Quantum ClientHellos (>1500 bytes) pre-segmented by Windows TCP stack
		partialMeta, err := tlsparse.ParsePartialClientHelloSNI(payload)
		if err == nil && partialMeta != nil && partialMeta.HasSNI {
			meta = partialMeta
		}
	}
	var sni string
	isSNILessPacket1 := false
	if meta != nil && meta.HasSNI {
		sni = meta.SNI
		if !h.matchesTarget(sni) {
			return h.fallbackPassThrough(packet, addr, sender)
		}
	} else {
		// Fix 2: Check if payload starts with a valid TLS Handshake ClientHello header
		// (ContentType 0x16, TLS Version 0x03 0x01..0x03, HandshakeType 0x01 ClientHello).
		// When Chromium permutes extensions, Post-Quantum key_share pushes the SNI extension into Packet 2.
		isClientHelloHeader := len(payload) >= 43 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
		if !isClientHelloHeader {
			return h.fallbackPassThrough(packet, addr, sender)
		}

		dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
		if isDoHBootstrapIP(dstIP) {
			return h.fallbackPassThrough(packet, addr, sender)
		}

		declaredRecLen := 5 + int(binary.BigEndian.Uint16(payload[3:5]))
		if declaredRecLen > len(payload) && h.pqTracker != nil {
			if flowKey, ok := ExtractIPv4TCPFlowKey(packet); ok {
				nextSeq := flowKey.SeqNum + uint32(len(payload))
				h.pqTracker.Record(flowKey.SrcIP, flowKey.DstIP, flowKey.SrcPort, flowKey.DstPort, nextSeq)
			}
		}

		defaultDesyncActive := !strings.EqualFold(h.cfg.DefaultProfile, "none")
		if !defaultDesyncActive {
			return h.fallbackPassThrough(packet, addr, sender)
		}

		isSNILessPacket1 = true
		sni = ""
	}

	currentFakeMode := h.cfg.FakePacketMode
	currentFakeTTL := h.cfg.FakeTTL
	currentSplitOffset := h.cfg.SplitOffset
	currentInterDelay := h.cfg.InterPacketDelay

	if h.autoLearner != nil && h.cfg.AutoLearn {
		defStrat := LearnedDomain{
			Stage:       0,
			FakeMode:    currentFakeMode,
			FakeTTL:     currentFakeTTL,
			SplitOffset: currentSplitOffset,
			DelayMS:     int(currentInterDelay / time.Millisecond),
			Explicit:    h.cfg.ExplicitOverrides,
		}

		if flowKey, ok := ExtractIPv4TCPFlowKey(packet); ok {
			domainForLearn := sni
			if domainForLearn == "" {
				domainForLearn = net.IPv4(packet[16], packet[17], packet[18], packet[19]).String()
			}
			strat, retransmitted, escalated := h.autoLearner.EvaluateFlow(flowKey, domainForLearn, defStrat)
			if retransmitted {
				h.stats.RetransmissionsDetected.Add(1)
			}
			if escalated {
				h.stats.StrategyEscalations.Add(1)
				h.stats.DomainsAutoLearned.Store(uint64(h.autoLearner.DomainCount()))
			}
			currentFakeMode = strat.FakeMode
			currentFakeTTL = strat.FakeTTL
			currentSplitOffset = strat.SplitOffset
			currentInterDelay = time.Duration(strat.DelayMS) * time.Millisecond
		}
	}

	attempt := 0
	if h.autoLearner != nil {
		if flowKey, ok := ExtractIPv4TCPFlowKey(packet); ok {
			attempt = h.autoLearner.FlowAttempt(flowKey)
		}
	}

	fakeEnabled, useTTL, useBadChk, err := ParseFakePacketMode(currentFakeMode)
	if err != nil {
		// Evasion mode invalid: safely fall back to sending real packet unmodified
		return h.fallbackPassThrough(packet, addr, sender)
	}

	if fakeEnabled {
		dummySNI := strings.TrimSpace(h.cfg.FakeSNI)
		if dummySNI == "" {
			dummySNI = DefaultFakeSNI
		}
		dummyPayload := packetlab.BuildDummyClientHello(dummySNI)

		var ttls []uint8
		if IsMultiTTL(currentFakeMode) {
			ttls = []uint8{4, 3}
			if currentFakeTTL > 0 && currentFakeTTL != 4 && currentFakeTTL != 3 {
				ttls = []uint8{currentFakeTTL, currentFakeTTL - 1}
			}
		} else if useTTL {
			ttl := currentFakeTTL
			if ttl == 0 {
				ttl = DefaultFakeTTL
			}
			ttls = []uint8{ttl}
		} else {
			ttls = []uint8{0}
		}

		for _, ttl := range ttls {
			fakePkt, synthErr := packetlab.SynthesizeFakeIPv4TCPPacket(packet, dummyPayload, ttl, useBadChk)
			if synthErr != nil {
				// If fake packet synthesis fails, safely fall back to sending the real packet unmodified
				return h.fallbackPassThrough(packet, addr, sender)
			}

			// NIC Hardware Offload Guarantee:
			// On the cloned divert.Address for the fake packet, explicitly set SetIPChecksum(true) and SetTCPChecksum(true).
			var fakeAddr Address
			if addr != nil {
				fakeAddr = *addr
			}
			fakeAddr.SetIPChecksum(true)
			fakeAddr.SetTCPChecksum(true)

			fakeSent := false
			if sender != nil {
				_, sendErr := sender.Send(fakePkt, &fakeAddr)
				if sendErr != nil {
					h.stats.FakeSendErrors.Add(1)
					// If sending the fake packet fails, proceed to send the real packet
				} else {
					fakeSent = true
					h.stats.FakePacketsInjected.Add(1)
					if useTTL {
						h.stats.FakeTTLCount.Add(1)
					}
					if useBadChk {
						h.stats.FakeBadChecksumCount.Add(1)
					}
					h.stats.PacketsSent.Add(1)
				}
			} else {
				fakeSent = true
				h.stats.FakePacketsInjected.Add(1)
				if useTTL {
					h.stats.FakeTTLCount.Add(1)
				}
				if useBadChk {
					h.stats.FakeBadChecksumCount.Add(1)
				}
				h.stats.PacketsSent.Add(1)
			}

			if fakeSent && h.cfg.FakePacketDelay > 0 {
				time.Sleep(h.cfg.FakePacketDelay)
			}
		}
	}

	// Transmit Real Packet second:
	// If splitting is configured, attempt Milestone 2.2 out-of-order segmentation.
	offsetSpec := currentSplitOffset
	if offsetSpec == "" {
		offsetSpec = "sni-mid"
	}

	splittingConfigured := offsetSpec != "none" && offsetSpec != "off"
	if splittingConfigured {
		var splitOffset int
		var err error
		if isSNILessPacket1 {
			// For SNI-less Packet 1 (e.g. Chromium permuted extensions with key_share ahead of SNI),
			// split at offset 2 (or numeric offset if specified) so the DPI middlebox is poisoned.
			if num, parseErr := strconv.Atoi(offsetSpec); parseErr == nil && num > 0 && num < len(payload) {
				splitOffset = num
			} else {
				splitOffset = 2
			}
		} else {
			splitOffset, err = strategy.ResolveSplitOffset(payload, meta, offsetSpec)
		}
		if (err == nil || isSNILessPacket1) && splitOffset > 0 && splitOffset < len(payload) {
			seg1, seg2, err := packetlab.SplitIPv4TCPPacket(packet, splitOffset)
			if err == nil {
				h.stats.PacketsSplit.Add(1)

				var segAddr Address
				if addr != nil {
					segAddr = *addr
				}
				segAddr.SetIPChecksum(true)
				segAddr.SetTCPChecksum(true)

				// Subsegment any piece exceeding MaxSegmentPayload = 1400 to prevent MTU drop
				seg2List, err2 := packetlab.SubsegmentIPv4TCPPacket(seg2, packetlab.MaxSegmentPayload)
				if err2 != nil {
					seg2List = [][]byte{seg2}
				}
				seg1List, err1 := packetlab.SubsegmentIPv4TCPPacket(seg1, packetlab.MaxSegmentPayload)
				if err1 != nil {
					seg1List = [][]byte{seg1}
				}

				if sender == nil {
					h.stats.OutOfOrderSegmentsInjected.Add(uint64(len(seg2List) + len(seg1List)))
					h.stats.PacketsSent.Add(uint64(len(seg2List) + len(seg1List)))
					h.logInfo("desynced TLS ClientHello",
						"dst_ip", net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(),
						"sni", sni,
						"fake_ttl", currentFakeTTL,
						"split_offset", offsetSpec,
						"attempt", attempt,
					)
					return nil
				}

				// Out-of-Order Injection:
				// 1. Emit Segment 2 chunks first
				for _, s := range seg2List {
					_, err = sender.Send(s, &segAddr)
					if err != nil {
						h.stats.SendErrors.Add(1)
						return fmt.Errorf("send segment 2: %w", err)
					}
					h.stats.OutOfOrderSegmentsInjected.Add(1)
					h.stats.PacketsSent.Add(1)
				}

				// 2. Configurable inter-packet delay
				if currentInterDelay > 0 {
					time.Sleep(currentInterDelay)
				}

				// 3. Emit Segment 1 chunks second
				for _, s := range seg1List {
					_, err = sender.Send(s, &segAddr)
					if err != nil {
						h.stats.SendErrors.Add(1)
						// CRITICAL: Once Segment 2 has been transmitted, never fall back to sending original packet!
						return fmt.Errorf("send segment 1: %w", err)
					}
					h.stats.OutOfOrderSegmentsInjected.Add(1)
					h.stats.PacketsSent.Add(1)
				}

				h.logInfo("desynced TLS ClientHello",
					"dst_ip", net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(),
					"sni", sni,
					"fake_ttl", currentFakeTTL,
					"split_offset", offsetSpec,
					"attempt", attempt,
				)
				return nil
			}
		}
	}

	// If splitting was configured but failed, count as a pass-through fallback.
	// If splitting was deliberately disabled and fake packets were injected, this is the intended normal transmission.
	if splittingConfigured {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	if fakeEnabled {
		h.logInfo("desynced TLS ClientHello",
			"dst_ip", net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(),
			"sni", sni,
			"fake_ttl", currentFakeTTL,
			"split_offset", "none",
			"attempt", attempt,
		)
		return h.sendPassThrough(packet, addr, sender)
	}
	return h.fallbackPassThrough(packet, addr, sender)
}

func (h *Harness) handleHTTPFragmentation(packet []byte, addr *Address, payloadOffset int, sender PacketSender) error {
	// 1. Non-IPv4 packets: safe pass-through fallback
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	// 2. Fragmented IPv4 datagrams cannot be split: safe pass-through fallback
	fragWord := binary.BigEndian.Uint16(packet[6:8])
	if fragWord&0x2000 != 0 || fragWord&0x1FFF != 0 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+20 {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	if dstPort != 80 {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	if payloadOffset <= 0 || payloadOffset >= len(packet) {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	payload := packet[payloadOffset:]
	if !isHTTPMethodPrefix(payload) {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	host, valStart, valEnd, found := packetlab.FindHTTPHost(payload)
	if !found {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	domainForMatch := host
	if hHost, _, hErr := net.SplitHostPort(host); hErr == nil {
		domainForMatch = hHost
	}

	if !h.matchesTarget(domainForMatch) {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	currentFakeMode := h.cfg.FakePacketMode
	currentFakeTTL := h.cfg.FakeTTL
	currentSplitOffset := h.cfg.SplitOffset
	currentInterDelay := h.cfg.InterPacketDelay

	if h.autoLearner != nil && h.cfg.AutoLearn {
		defStrat := LearnedDomain{
			Stage:       0,
			FakeMode:    currentFakeMode,
			FakeTTL:     currentFakeTTL,
			SplitOffset: currentSplitOffset,
			DelayMS:     int(currentInterDelay / time.Millisecond),
			Explicit:    h.cfg.ExplicitOverrides,
		}

		if flowKey, ok := ExtractIPv4TCPFlowKey(packet); ok {
			strat, retransmitted, escalated := h.autoLearner.EvaluateFlow(flowKey, domainForMatch, defStrat)
			if retransmitted {
				h.stats.RetransmissionsDetected.Add(1)
			}
			if escalated {
				h.stats.StrategyEscalations.Add(1)
				h.stats.DomainsAutoLearned.Store(uint64(h.autoLearner.DomainCount()))
			}
			currentFakeMode = strat.FakeMode
			currentFakeTTL = strat.FakeTTL
			currentSplitOffset = strat.SplitOffset
			currentInterDelay = time.Duration(strat.DelayMS) * time.Millisecond
		}
	}

	fakeEnabled, useTTL, useBadChk, err := ParseFakePacketMode(currentFakeMode)
	if err != nil {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	if fakeEnabled {
		dummySNI := strings.TrimSpace(h.cfg.FakeSNI)
		if dummySNI == "" {
			dummySNI = DefaultFakeSNI
		}
		dummyPayload := packetlab.BuildDummyHTTPRequest(dummySNI)

		var ttls []uint8
		if IsMultiTTL(currentFakeMode) {
			ttls = []uint8{4, 3}
			if currentFakeTTL > 0 && currentFakeTTL != 4 && currentFakeTTL != 3 {
				ttls = []uint8{currentFakeTTL, currentFakeTTL - 1}
			}
		} else if useTTL {
			ttl := currentFakeTTL
			if ttl == 0 {
				ttl = DefaultFakeTTL
			}
			ttls = []uint8{ttl}
		} else {
			ttls = []uint8{0}
		}

		for _, ttl := range ttls {
			fakePkt, synthErr := packetlab.SynthesizeFakeIPv4TCPPacket(packet, dummyPayload, ttl, useBadChk)
			if synthErr != nil {
				return h.fallbackPassThrough(packet, addr, sender)
			}

			var fakeAddr Address
			if addr != nil {
				fakeAddr = *addr
			}
			fakeAddr.SetIPChecksum(true)
			fakeAddr.SetTCPChecksum(true)

			fakeSent := false
			if sender != nil {
				_, sendErr := sender.Send(fakePkt, &fakeAddr)
				if sendErr != nil {
					h.stats.FakeSendErrors.Add(1)
				} else {
					fakeSent = true
					h.stats.FakePacketsInjected.Add(1)
					if useTTL {
						h.stats.FakeTTLCount.Add(1)
					}
					if useBadChk {
						h.stats.FakeBadChecksumCount.Add(1)
					}
					h.stats.PacketsSent.Add(1)
				}
			} else {
				fakeSent = true
				h.stats.FakePacketsInjected.Add(1)
				if useTTL {
					h.stats.FakeTTLCount.Add(1)
				}
				if useBadChk {
					h.stats.FakeBadChecksumCount.Add(1)
				}
				h.stats.PacketsSent.Add(1)
			}

			if fakeSent && h.cfg.FakePacketDelay > 0 {
				time.Sleep(h.cfg.FakePacketDelay)
			}
		}
	}

	offsetSpec := currentSplitOffset
	if offsetSpec == "" {
		offsetSpec = "sni-mid"
	}

	splittingConfigured := offsetSpec != "none" && offsetSpec != "off"
	if splittingConfigured {
		normSpec := strings.ToLower(strings.TrimSpace(offsetSpec))
		var splitOffset int
		hostValLen := valEnd - valStart

		switch normSpec {
		case "sni-start", "host-start":
			splitOffset = valStart
		case "sni-end", "host-end":
			splitOffset = valEnd
		case "sni-mid", "host-mid":
			if hostValLen >= 2 {
				splitOffset = valStart + hostValLen/2
			} else {
				splitOffset = valStart
			}
		default:
			if val, err := strconv.Atoi(normSpec); err == nil && val > 0 && val < len(payload) {
				splitOffset = val
			} else if hostValLen >= 2 {
				splitOffset = valStart + hostValLen/2
			} else {
				splitOffset = valStart
			}
		}

		if splitOffset > 0 && splitOffset < len(payload) {
			seg1, seg2, err := packetlab.SplitIPv4TCPPacket(packet, splitOffset)
			if err == nil {
				h.stats.PacketsSplit.Add(1)

				var segAddr Address
				if addr != nil {
					segAddr = *addr
				}
				segAddr.SetIPChecksum(true)
				segAddr.SetTCPChecksum(true)

				// Subsegment any piece exceeding MaxSegmentPayload = 1400 to prevent MTU drop
				seg2List, err2 := packetlab.SubsegmentIPv4TCPPacket(seg2, packetlab.MaxSegmentPayload)
				if err2 != nil {
					seg2List = [][]byte{seg2}
				}
				seg1List, err1 := packetlab.SubsegmentIPv4TCPPacket(seg1, packetlab.MaxSegmentPayload)
				if err1 != nil {
					seg1List = [][]byte{seg1}
				}

				if sender == nil {
					h.stats.OutOfOrderSegmentsInjected.Add(uint64(len(seg2List) + len(seg1List)))
					h.stats.PacketsSent.Add(uint64(len(seg2List) + len(seg1List)))
					return nil
				}

				// Emit Segment 2 chunks first
				for _, s := range seg2List {
					_, err = sender.Send(s, &segAddr)
					if err != nil {
						h.stats.SendErrors.Add(1)
						return fmt.Errorf("send segment 2: %w", err)
					}
					h.stats.OutOfOrderSegmentsInjected.Add(1)
					h.stats.PacketsSent.Add(1)
				}

				if currentInterDelay > 0 {
					time.Sleep(currentInterDelay)
				}

				// Emit Segment 1 chunks second
				for _, s := range seg1List {
					_, err = sender.Send(s, &segAddr)
					if err != nil {
						h.stats.SendErrors.Add(1)
						return fmt.Errorf("send segment 1: %w", err)
					}
					h.stats.OutOfOrderSegmentsInjected.Add(1)
					h.stats.PacketsSent.Add(1)
				}

				return nil
			}
		}
	}

	if splittingConfigured {
		return h.fallbackPassThrough(packet, addr, sender)
	}
	if fakeEnabled {
		return h.sendPassThrough(packet, addr, sender)
	}
	return h.fallbackPassThrough(packet, addr, sender)
}

func (h *Harness) handlePacket2Fragmentation(packet []byte, addr *Address, payloadOffset int, sender PacketSender) error {
	payload := packet[payloadOffset:]
	var sni string
	splitOffset := len(payload) / 2
	if splitOffset <= 0 {
		splitOffset = 1
	}

	cont, err := tlsparse.FindContinuationSNI(payload)
	if err == nil && cont != nil {
		sni = cont.SNI
		if cont.SplitOffset > 0 && cont.SplitOffset < len(payload) {
			splitOffset = cont.SplitOffset
		}
	}

	fakeTTL := uint8(4)
	if h.cfg.FakeTTL > 0 {
		fakeTTL = h.cfg.FakeTTL
	}

	// 1. Synthesize fake packet at Packet 2 SeqNum with dummy payload of same length
	dummyPayload := make([]byte, len(payload))
	fakePkt, synthErr := packetlab.SynthesizeFakeIPv4TCPPacket(packet, dummyPayload, fakeTTL, false)
	if synthErr == nil {
		var fakeAddr Address
		if addr != nil {
			fakeAddr = *addr
		}
		fakeAddr.SetIPChecksum(true)
		fakeAddr.SetTCPChecksum(true)

		if sender != nil {
			_, sendErr := sender.Send(fakePkt, &fakeAddr)
			if sendErr != nil {
				h.stats.FakeSendErrors.Add(1)
			} else {
				h.stats.FakePacketsInjected.Add(1)
				h.stats.FakeTTLCount.Add(1)
				h.stats.PacketsSent.Add(1)
			}
		} else {
			h.stats.FakePacketsInjected.Add(1)
			h.stats.FakeTTLCount.Add(1)
			h.stats.PacketsSent.Add(1)
		}
	}

	// 2. Split Packet 2 out-of-order right at the middle of the SNI (sni-mid)
	seg1, seg2, splitErr := packetlab.SplitIPv4TCPPacket(packet, splitOffset)
	if splitErr != nil {
		return h.fallbackPassThrough(packet, addr, sender)
	}

	h.stats.PacketsSplit.Add(1)
	h.stats.Packet2Desynced.Add(1)

	var segAddr Address
	if addr != nil {
		segAddr = *addr
	}
	segAddr.SetIPChecksum(true)
	segAddr.SetTCPChecksum(true)

	seg2List, err2 := packetlab.SubsegmentIPv4TCPPacket(seg2, packetlab.MaxSegmentPayload)
	if err2 != nil {
		seg2List = [][]byte{seg2}
	}
	seg1List, err1 := packetlab.SubsegmentIPv4TCPPacket(seg1, packetlab.MaxSegmentPayload)
	if err1 != nil {
		seg1List = [][]byte{seg1}
	}

	if sender == nil {
		h.stats.OutOfOrderSegmentsInjected.Add(uint64(len(seg2List) + len(seg1List)))
		h.stats.PacketsSent.Add(uint64(len(seg2List) + len(seg1List)))
		h.logInfo("desynced TLS ClientHello Packet 2",
			"dst_ip", net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(),
			"sni", sni,
			"fake_ttl", fakeTTL,
			"split_offset", "sni-mid",
		)
		return nil
	}

	// Send Segment 2 first
	for _, s := range seg2List {
		_, err := sender.Send(s, &segAddr)
		if err != nil {
			h.stats.SendErrors.Add(1)
			return fmt.Errorf("send packet 2 segment 2: %w", err)
		}
		h.stats.OutOfOrderSegmentsInjected.Add(1)
		h.stats.PacketsSent.Add(1)
	}

	if h.cfg.InterPacketDelay > 0 {
		time.Sleep(h.cfg.InterPacketDelay)
	}

	// Send Segment 1 second
	for _, s := range seg1List {
		_, err := sender.Send(s, &segAddr)
		if err != nil {
			h.stats.SendErrors.Add(1)
			return fmt.Errorf("send packet 2 segment 1: %w", err)
		}
		h.stats.OutOfOrderSegmentsInjected.Add(1)
		h.stats.PacketsSent.Add(1)
	}

	h.logInfo("desynced TLS ClientHello Packet 2",
		"dst_ip", net.IPv4(packet[16], packet[17], packet[18], packet[19]).String(),
		"sni", sni,
		"fake_ttl", fakeTTL,
		"split_offset", "sni-mid",
	)
	return nil
}

func (h *Harness) handleDNSInterception(packet []byte, addr *Address, payloadOffset int, sender PacketSender) error {
	if len(packet) > 0 && (packet[0]>>4) == 6 {
		return h.handleIPv6DNS(packet, addr, payloadOffset, sender)
	}

	h.stats.DNSQueriesIntercepted.Add(1)

	if len(packet) < 28 || (packet[0]>>4) != 4 {
		h.stats.DNSFallbacks.Add(1)
		return nil
	}
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+8 {
		h.stats.DNSFallbacks.Add(1)
		return nil
	}
	dnsPayload := packet[ihl+8:]

	query, err := dnsdoh.ParseDNSQuery(dnsPayload)
	if err != nil {
		h.stats.DNSFallbacks.Add(1)
		return nil
	}

	h.logInfo("intercepted UDP-53 query", "version", 4, "domain", query.Question.Name, "qtype", query.Question.Type)

	if query.Question.Class != dnsdoh.ClassINET {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPChecksum(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	isTarget := h.matchesExplicitTarget(query.Question.Name)

	if query.Question.Type == dnsdoh.TypeAAAA ||
		query.Question.Type == dnsdoh.TypeHTTPS ||
		query.Question.Type == dnsdoh.TypeSVCB ||
		query.Question.Type == dnsdoh.TypePTR ||
		strings.HasSuffix(query.Question.Name, ".in-addr.arpa") ||
		strings.HasSuffix(query.Question.Name, ".ip6.arpa") ||
		(isTarget && query.Question.Type != dnsdoh.TypeA) {
		respWire, err := dnsdoh.BuildDNSResponse(query, nil, 60*time.Second)
		if err == nil {
			inboundPkt, err := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, respWire)
			if err == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPChecksum(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inboundPkt, &respAddr)
				}
				h.stats.DNSQueriesResolvedDoH.Add(1)
				h.stats.PacketsSent.Add(1)
				return nil
			}
		}
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPChecksum(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	if query.Question.Type != dnsdoh.TypeA {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPChecksum(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	select {
	case h.dnsSem <- struct{}{}:
	default:
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPChecksum(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	pktCopy := append([]byte(nil), packet...)
	var addrCopy Address
	if addr != nil {
		addrCopy = *addr
	}

	go func(origPkt []byte, origAddr Address, q *dnsdoh.DNSQuery) {
		defer func() {
			<-h.dnsSem
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ips, ttl, isNoData, err := h.cfg.DNSResolver.ResolveQueryType(ctx, q.Question.Name, q.Question.Type)
		if err != nil && !isNoData {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPChecksum(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		respWire, err := dnsdoh.BuildDNSResponse(q, ips, ttl)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPChecksum(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		inboundPkt, err := packetlab.SynthesizeDNSResponseIPv4UDPPacket(origPkt, respWire)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPChecksum(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		respAddr := origAddr
		respAddr.SetOutbound(false)
		respAddr.SetIPChecksum(true)
		respAddr.SetUDPChecksum(true)

		if sender != nil {
			_, sendErr := sender.Send(inboundPkt, &respAddr)
			if sendErr != nil {
				h.stats.SendErrors.Add(1)
				h.logError("DoH response send failed", "domain", q.Question.Name, "error", sendErr)
				return
			}
		}
		h.stats.DNSQueriesResolvedDoH.Add(1)
		h.stats.PacketsSent.Add(1)
		h.logInfo("resolved DNS via DoH", "domain", q.Question.Name, "ips", ips)
	}(pktCopy, addrCopy, query)

	return nil
}

func (h *Harness) handleIPv6DNS(packet []byte, addr *Address, payloadOffset int, sender PacketSender) error {
	h.stats.DNSQueriesIntercepted.Add(1)

	if payloadOffset <= 0 || payloadOffset >= len(packet) {
		h.stats.DNSFallbacks.Add(1)
		return nil
	}
	dnsPayload := packet[payloadOffset:]

	query, err := dnsdoh.ParseDNSQuery(dnsPayload)
	if err != nil {
		h.stats.DNSFallbacks.Add(1)
		return nil
	}

	h.logInfo("intercepted UDP-53 query", "version", 6, "domain", query.Question.Name, "qtype", query.Question.Type)

	if query.Question.Class != dnsdoh.ClassINET {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPv6(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	isTarget := h.matchesExplicitTarget(query.Question.Name)

	if query.Question.Type == dnsdoh.TypeAAAA ||
		query.Question.Type == dnsdoh.TypeHTTPS ||
		query.Question.Type == dnsdoh.TypeSVCB ||
		query.Question.Type == dnsdoh.TypePTR ||
		strings.HasSuffix(query.Question.Name, ".in-addr.arpa") ||
		strings.HasSuffix(query.Question.Name, ".ip6.arpa") ||
		(isTarget && query.Question.Type != dnsdoh.TypeA) {
		respWire, err := dnsdoh.BuildDNSResponse(query, nil, 60*time.Second)
		if err == nil {
			inboundPkt, err := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, respWire)
			if err == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPv6(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inboundPkt, &respAddr)
				}
				h.stats.DNSQueriesResolvedDoH.Add(1)
				h.stats.PacketsSent.Add(1)
				return nil
			}
		}
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPv6(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	if query.Question.Type != dnsdoh.TypeA {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPv6(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	select {
	case h.dnsSem <- struct{}{}:
	default:
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				var respAddr Address
				if addr != nil {
					respAddr = *addr
				}
				respAddr.SetOutbound(false)
				respAddr.SetIPv6(true)
				respAddr.SetUDPChecksum(true)
				if sender != nil {
					_, _ = sender.Send(inPkt, &respAddr)
				}
				h.stats.PacketsSent.Add(1)
			}
		}
		return nil
	}

	pktCopy := append([]byte(nil), packet...)
	var addrCopy Address
	if addr != nil {
		addrCopy = *addr
	}

	go func(origPkt []byte, origAddr Address, q *dnsdoh.DNSQuery) {
		defer func() {
			<-h.dnsSem
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ips, ttl, isNoData, err := h.cfg.DNSResolver.ResolveQueryType(ctx, q.Question.Name, q.Question.Type)
		if err != nil && !isNoData {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPv6(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		respWire, err := dnsdoh.BuildDNSResponse(q, ips, ttl)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPv6(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		inboundPkt, err := packetlab.SynthesizeDNSResponseIPv6UDPPacket(origPkt, respWire)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", q.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(q); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(origPkt, sfWire); inErr == nil {
					respAddr := origAddr
					respAddr.SetOutbound(false)
					respAddr.SetIPv6(true)
					respAddr.SetUDPChecksum(true)
					if sender != nil {
						_, _ = sender.Send(inPkt, &respAddr)
					}
					h.stats.PacketsSent.Add(1)
				}
			}
			return
		}

		respAddr := origAddr
		respAddr.SetOutbound(false)
		respAddr.SetIPv6(true)
		respAddr.SetUDPChecksum(true)

		if sender != nil {
			_, sendErr := sender.Send(inboundPkt, &respAddr)
			if sendErr != nil {
				h.stats.SendErrors.Add(1)
				h.logError("DoH response send failed", "domain", q.Question.Name, "error", sendErr)
				return
			}
		}
		h.stats.DNSQueriesResolvedDoH.Add(1)
		h.stats.PacketsSent.Add(1)
		h.logInfo("resolved DNS via DoH", "domain", q.Question.Name, "ips", ips)
	}(pktCopy, addrCopy, query)

	return nil
}

func (h *Harness) processIPv6DNS(packet []byte, addr *Address, payloadOffset int) (FastPathAction, []byte, error) {
	h.stats.DNSQueriesIntercepted.Add(1)

	if payloadOffset <= 0 || payloadOffset >= len(packet) {
		h.stats.DNSFallbacks.Add(1)
		return ActionDropDNSIPv6, nil, nil
	}
	dnsPayload := packet[payloadOffset:]

	query, err := dnsdoh.ParseDNSQuery(dnsPayload)
	if err != nil {
		h.stats.DNSFallbacks.Add(1)
		return ActionDropDNSIPv6, nil, nil
	}

	h.logInfo("intercepted UDP-53 query", "version", 6, "domain", query.Question.Name, "qtype", query.Question.Type)

	if query.Question.Class != dnsdoh.ClassINET {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	isTarget := h.matchesExplicitTarget(query.Question.Name)

	if query.Question.Type == dnsdoh.TypeAAAA ||
		query.Question.Type == dnsdoh.TypeHTTPS ||
		query.Question.Type == dnsdoh.TypeSVCB ||
		query.Question.Type == dnsdoh.TypePTR ||
		strings.HasSuffix(query.Question.Name, ".in-addr.arpa") ||
		strings.HasSuffix(query.Question.Name, ".ip6.arpa") ||
		(isTarget && query.Question.Type != dnsdoh.TypeA) {
		respWire, err := dnsdoh.BuildDNSResponse(query, nil, 60*time.Second)
		if err == nil {
			inboundPkt, err := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, respWire)
			if err == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.DNSQueriesResolvedDoH.Add(1)
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inboundPkt, nil
			}
		}
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	if query.Question.Type != dnsdoh.TypeA {
		h.stats.DNSFallbacks.Add(1)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, ttl, isNoData, err := h.cfg.DNSResolver.ResolveQueryType(ctx, query.Question.Name, query.Question.Type)
	if err != nil && !isNoData {
		h.stats.DNSFallbacks.Add(1)
		h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	respWire, err := dnsdoh.BuildDNSResponse(query, ips, ttl)
	if err != nil {
		h.stats.DNSFallbacks.Add(1)
		h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	inboundPkt, err := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, respWire)
	if err != nil {
		h.stats.DNSFallbacks.Add(1)
		h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
		if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
			if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv6UDPPacket(packet, sfWire); inErr == nil {
				if addr != nil {
					addr.SetOutbound(false)
					addr.SetIPv6(true)
					addr.SetUDPChecksum(true)
				}
				h.stats.PacketsSent.Add(1)
				return ActionDropDNSIPv6, inPkt, nil
			}
		}
		return ActionDropDNSIPv6, nil, nil
	}

	if addr != nil {
		addr.SetOutbound(false)
		addr.SetIPv6(true)
		addr.SetUDPChecksum(true)
	}

	h.stats.DNSQueriesResolvedDoH.Add(1)
	h.stats.PacketsSent.Add(1)
	h.logInfo("resolved DNS via DoH", "domain", query.Question.Name, "ips", ips)
	return ActionDropDNSIPv6, inboundPkt, nil
}

func (h *Harness) executeDNSInterception(packet []byte, addr *Address, payloadOffset int, sender PacketSender) {
	_ = h.handleDNSInterception(packet, addr, payloadOffset, sender)
}

func (h *Harness) executeIPv6DNS(packet []byte, addr *Address, payloadOffset int, sender PacketSender) {
	_ = h.handleIPv6DNS(packet, addr, payloadOffset, sender)
}

// HandlePacket processes a captured packet through the harness pipeline and transmits
// resulting packets using the provided sender (or configured sender/handle if nil).
func (h *Harness) HandlePacket(packet []byte, addr *Address, sender PacketSender) error {
	h.stats.PacketsRecv.Add(1)

	if sender == nil {
		sender = h.getSender()
	}

	// Fix 3: Sinkhole Guard for 195.175.254.2 (Türk Telekom BTK sinkhole IP)
	if (addr == nil || addr.Outbound()) && len(packet) >= 20 && (packet[0]>>4) == 4 && packet[9] == 6 &&
		packet[16] == 195 && packet[17] == 175 && packet[18] == 254 && packet[19] == 2 {
		h.handleSinkholeBlock(packet, addr, sender)
		return nil
	}

	// Intercept Packet 2 of multi-packet Post-Quantum TLS ClientHello before FastPathInspect
	if h.pqTracker != nil && len(packet) >= 40 && (packet[0]>>4) == 4 && packet[9] == 6 && (addr == nil || addr.Outbound()) {
		ihl := int(packet[0]&0x0F) * 4
		if ihl >= 20 && len(packet) >= ihl+20 {
			tcpDataOffset := int(packet[ihl+12]>>4) * 4
			if tcpDataOffset >= 20 && len(packet) > ihl+tcpDataOffset {
				payloadLen := len(packet) - (ihl + tcpDataOffset)
				if payloadLen > 0 {
					var srcIP, dstIP [4]byte
					copy(srcIP[:], packet[12:16])
					copy(dstIP[:], packet[16:20])
					srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
					dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
					seqNum := binary.BigEndian.Uint32(packet[ihl+4 : ihl+8])

					if dstPort == 443 && h.pqTracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, seqNum) {
						return h.handlePacket2Fragmentation(packet, addr, ihl+tcpDataOffset, sender)
					}
				}
			}
		}
	}

	action, payloadOffset := FastPathInspect(packet)
	switch action {
	case ActionDropQUIC:
		if h.cfg.DropQUIC {
			h.stats.QUICDropped.Add(1)
			return nil
		}
		return h.sendPassThrough(packet, addr, sender)

	case ActionDropSinkhole:
		if addr != nil && !addr.Outbound() {
			return h.sendPassThrough(packet, addr, sender)
		}
		h.handleSinkholeBlock(packet, addr, sender)
		return nil

	case ActionDropTCP53:
		if addr != nil && !addr.Outbound() {
			return h.sendPassThrough(packet, addr, sender)
		}
		h.logWarn("blocked unencrypted TCP-53 DNS leak")
		return nil

	case ActionPassFastPath:
		h.stats.TCPFastPath.Add(1)
		return h.sendPassThrough(packet, addr, sender)

	case ActionInspectCandidate:
		h.stats.TCPCandidate.Add(1)

		if h.cfg.Handler != nil {
			modified, err := h.cfg.Handler.HandleCandidate(packet, addr, payloadOffset)
			if err != nil {
				return h.fallbackPassThrough(packet, addr, sender)
			}
			return h.sendPassThrough(modified, addr, sender)
		}

		if payloadOffset > 0 && payloadOffset < len(packet) {
			if packet[payloadOffset] == 0x16 {
				h.stats.CandidateHandshakes.Add(1)
				return h.handleCandidateFragmentation(packet, addr, payloadOffset, sender)
			}
			if h.cfg.DesyncHTTP && isHTTPMethodPrefix(packet[payloadOffset:]) {
				h.stats.CandidateHandshakes.Add(1)
				return h.handleHTTPFragmentation(packet, addr, payloadOffset, sender)
			}
		}

		// Non-handshake candidate or HTTP with desync disabled: clean pass-through
		return h.sendPassThrough(packet, addr, sender)

	case ActionInterceptDNS:
		if !h.cfg.InterceptDNS || h.cfg.DNSResolver == nil {
			return nil
		}
		if addr != nil && !addr.Outbound() {
			return h.sendPassThrough(packet, addr, sender)
		}
		return h.handleDNSInterception(packet, addr, payloadOffset, sender)

	case ActionDropDNSIPv6:
		if !h.cfg.InterceptDNS {
			return nil
		}
		if addr != nil && !addr.Outbound() {
			return h.sendPassThrough(packet, addr, sender)
		}
		if h.cfg.DNSResolver != nil {
			return h.handleIPv6DNS(packet, addr, payloadOffset, sender)
		}
		h.stats.DNSQueriesIntercepted.Add(1)
		return nil

	case ActionDropIPv6TCP:
		if addr != nil && !addr.Outbound() {
			return h.sendPassThrough(packet, addr, sender)
		}
		// Immediately drop outbound IPv6 TCP 80/443 to force Happy Eyeballs (RFC 8305) fallback to IPv4
		return nil

	default:
		return h.sendPassThrough(packet, addr, sender)
	}
}

// ProcessPacket processes an individual packet through the harness pipeline.
// Useful for deterministic in-memory testing without a live driver handle.
func (h *Harness) ProcessPacket(packet []byte, addr *Address) (FastPathAction, []byte, error) {
	h.stats.PacketsRecv.Add(1)

	// Fix 3: Sinkhole Guard for 195.175.254.2 (Türk Telekom BTK sinkhole IP)
	if (addr == nil || addr.Outbound()) && len(packet) >= 20 && (packet[0]>>4) == 4 && packet[9] == 6 &&
		packet[16] == 195 && packet[17] == 175 && packet[18] == 254 && packet[19] == 2 {
		h.handleSinkholeBlock(packet, addr, h.cfg.Sender)
		return ActionDropSinkhole, nil, nil
	}

	// Intercept Packet 2 of multi-packet Post-Quantum TLS ClientHello before FastPathInspect
	if h.pqTracker != nil && len(packet) >= 40 && (packet[0]>>4) == 4 && packet[9] == 6 && (addr == nil || addr.Outbound()) {
		ihl := int(packet[0]&0x0F) * 4
		if ihl >= 20 && len(packet) >= ihl+20 {
			tcpDataOffset := int(packet[ihl+12]>>4) * 4
			if tcpDataOffset >= 20 && len(packet) > ihl+tcpDataOffset {
				payloadLen := len(packet) - (ihl + tcpDataOffset)
				if payloadLen > 0 {
					var srcIP, dstIP [4]byte
					copy(srcIP[:], packet[12:16])
					copy(dstIP[:], packet[16:20])
					srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
					dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
					seqNum := binary.BigEndian.Uint32(packet[ihl+4 : ihl+8])

					if dstPort == 443 && h.pqTracker.MatchAndRemove(srcIP, dstIP, srcPort, dstPort, seqNum) {
						h.stats.CandidateHandshakes.Add(1)
						if h.cfg.Sender != nil {
							err := h.handlePacket2Fragmentation(packet, addr, ihl+tcpDataOffset, h.cfg.Sender)
							if err != nil {
								return ActionInspectCandidate, nil, err
							}
							return ActionInspectCandidate, nil, nil
						}
						_ = h.handlePacket2Fragmentation(packet, addr, ihl+tcpDataOffset, nil)
						return ActionInspectCandidate, packet, nil
					}
				}
			}
		}
	}

	action, payloadOffset := FastPathInspect(packet)
	switch action {
	case ActionDropQUIC:
		if h.cfg.DropQUIC {
			h.stats.QUICDropped.Add(1)
			return ActionDropQUIC, nil, nil
		}
		h.stats.PacketsSent.Add(1)
		return ActionPassFastPath, packet, nil

	case ActionDropSinkhole:
		if addr != nil && !addr.Outbound() {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		h.handleSinkholeBlock(packet, addr, h.cfg.Sender)
		return ActionDropSinkhole, nil, nil

	case ActionDropTCP53:
		if addr != nil && !addr.Outbound() {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		h.logWarn("blocked unencrypted TCP-53 DNS leak")
		return ActionDropTCP53, nil, nil

	case ActionPassFastPath:
		h.stats.TCPFastPath.Add(1)
		h.stats.PacketsSent.Add(1)
		return ActionPassFastPath, packet, nil

	case ActionInspectCandidate:
		h.stats.TCPCandidate.Add(1)
		if h.cfg.Handler != nil {
			modified, err := h.cfg.Handler.HandleCandidate(packet, addr, payloadOffset)
			if err != nil {
				return action, nil, err
			}
			h.stats.PacketsSent.Add(1)
			return ActionInspectCandidate, modified, nil
		}

		if payloadOffset > 0 && payloadOffset < len(packet) {
			if packet[payloadOffset] == 0x16 {
				h.stats.CandidateHandshakes.Add(1)
				if h.cfg.Sender != nil {
					err := h.handleCandidateFragmentation(packet, addr, payloadOffset, h.cfg.Sender)
					if err != nil {
						return ActionInspectCandidate, nil, err
					}
					return ActionInspectCandidate, nil, nil
				}
				h.stats.PassThroughFallbacks.Add(1)
				h.stats.PacketsSent.Add(1)
				return ActionInspectCandidate, packet, nil
			}
			if h.cfg.DesyncHTTP && isHTTPMethodPrefix(packet[payloadOffset:]) {
				h.stats.CandidateHandshakes.Add(1)
				if h.cfg.Sender != nil {
					err := h.handleHTTPFragmentation(packet, addr, payloadOffset, h.cfg.Sender)
					if err != nil {
						return ActionInspectCandidate, nil, err
					}
					return ActionInspectCandidate, nil, nil
				}
				h.stats.PassThroughFallbacks.Add(1)
				h.stats.PacketsSent.Add(1)
				return ActionInspectCandidate, packet, nil
			}
		}

		h.stats.PacketsSent.Add(1)
		return ActionInspectCandidate, packet, nil

	case ActionInterceptDNS:
		if !h.cfg.InterceptDNS || h.cfg.DNSResolver == nil {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		if addr != nil && !addr.Outbound() {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}

		h.stats.DNSQueriesIntercepted.Add(1)

		if len(packet) < 28 || (packet[0]>>4) != 4 {
			h.stats.DNSFallbacks.Add(1)
			return ActionInterceptDNS, nil, nil
		}
		ihl := int(packet[0]&0x0F) * 4
		if len(packet) < ihl+8 {
			h.stats.DNSFallbacks.Add(1)
			return ActionInterceptDNS, nil, nil
		}
		dnsPayload := packet[ihl+8:]

		query, err := dnsdoh.ParseDNSQuery(dnsPayload)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			return ActionInterceptDNS, nil, nil
		}

		h.logInfo("intercepted UDP-53 query", "version", 4, "domain", query.Question.Name, "qtype", query.Question.Type)

		if query.Question.Class != dnsdoh.ClassINET {
			h.stats.DNSFallbacks.Add(1)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		isTarget := h.matchesExplicitTarget(query.Question.Name)

		if query.Question.Type == dnsdoh.TypeAAAA ||
			query.Question.Type == dnsdoh.TypeHTTPS ||
			query.Question.Type == dnsdoh.TypeSVCB ||
			query.Question.Type == dnsdoh.TypePTR ||
			strings.HasSuffix(query.Question.Name, ".in-addr.arpa") ||
			strings.HasSuffix(query.Question.Name, ".ip6.arpa") ||
			(isTarget && query.Question.Type != dnsdoh.TypeA) {
			respWire, err := dnsdoh.BuildDNSResponse(query, nil, 60*time.Second)
			if err == nil {
				inboundPkt, err := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, respWire)
				if err == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.DNSQueriesResolvedDoH.Add(1)
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inboundPkt, nil
				}
			}
			h.stats.DNSFallbacks.Add(1)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		if query.Question.Type != dnsdoh.TypeA {
			h.stats.DNSFallbacks.Add(1)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ips, ttl, isNoData, err := h.cfg.DNSResolver.ResolveQueryType(ctx, query.Question.Name, query.Question.Type)
		if err != nil && !isNoData {
			h.stats.DNSFallbacks.Add(1)
			h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		respWire, err := dnsdoh.BuildDNSResponse(query, ips, ttl)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.stats.PacketsSent.Add(1)
			h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		inboundPkt, err := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, respWire)
		if err != nil {
			h.stats.DNSFallbacks.Add(1)
			h.stats.PacketsSent.Add(1)
			h.logError("DoH resolution failed", "domain", query.Question.Name, "error", err)
			if sfWire, sfErr := dnsdoh.BuildDNSServFailResponse(query); sfErr == nil {
				if inPkt, inErr := packetlab.SynthesizeDNSResponseIPv4UDPPacket(packet, sfWire); inErr == nil {
					if addr != nil {
						addr.SetOutbound(false)
						addr.SetIPChecksum(true)
						addr.SetUDPChecksum(true)
					}
					h.stats.PacketsSent.Add(1)
					return ActionInterceptDNS, inPkt, nil
				}
			}
			return ActionInterceptDNS, nil, nil
		}

		if addr != nil {
			addr.SetOutbound(false)
			addr.SetIPChecksum(true)
			addr.SetUDPChecksum(true)
		}

		h.stats.DNSQueriesResolvedDoH.Add(1)
		h.stats.PacketsSent.Add(1)
		h.logInfo("resolved DNS via DoH", "domain", query.Question.Name, "ips", ips)
		return ActionInterceptDNS, inboundPkt, nil

	case ActionDropDNSIPv6:
		if !h.cfg.InterceptDNS {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		if addr != nil && !addr.Outbound() {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		if h.cfg.DNSResolver != nil {
			return h.processIPv6DNS(packet, addr, payloadOffset)
		}
		h.stats.DNSQueriesIntercepted.Add(1)
		return ActionDropDNSIPv6, nil, nil

	case ActionDropIPv6TCP:
		if addr != nil && !addr.Outbound() {
			h.stats.PacketsSent.Add(1)
			return ActionPassFastPath, packet, nil
		}
		return ActionDropIPv6TCP, nil, nil

	default:
		h.stats.PacketsSent.Add(1)
		return ActionPassFastPath, packet, nil
	}
}

// IsInterceptDNSEnabled reports whether transparent UDP-53 DNS interception is configured.
func (h *Harness) IsInterceptDNSEnabled() bool {
	return h.cfg.InterceptDNS
}

// IsAutoLearnEnabled reports whether adaptive retransmission auto-learning is active.
func (h *Harness) IsAutoLearnEnabled() bool {
	return h.autoLearner != nil && h.autoLearner.Enabled()
}

// Filter returns the active WinDivert filter expression configured for the harness.
func (h *Harness) Filter() string {
	return h.cfg.Filter
}

func (h *Harness) startLocked() error {
	if h.handle != InvalidHandle {
		return errors.New("harness already started")
	}

	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("check process elevation: %w", err)
	}
	if !elevated {
		return errors.New("administrative privileges required to open WinDivert handle")
	}

	if !IsAvailable() {
		return errors.New("WinDivert.dll not available")
	}

	if h.cfg.InterceptDNS && (h.cfg.Filter == "" || h.cfg.Filter == FilterOutboundProduction) {
		h.cfg.Filter = FilterOutboundWithDNS
	}

	handle, err := Open(h.cfg.Filter, LayerNetwork, h.cfg.Priority, 0)
	if err != nil {
		return fmt.Errorf("open WinDivert handle: %w", err)
	}

	if h.cfg.Logger != nil {
		h.cfg.Logger.Info("WinDivert handle opened", "filter", h.cfg.Filter, "layer", LayerNetwork, "priority", h.cfg.Priority)
	} else {
		slog.Info("WinDivert handle opened", "filter", h.cfg.Filter, "layer", LayerNetwork, "priority", h.cfg.Priority)
	}

	if err := SetParam(handle, ParamQueueLength, uint64(h.cfg.QueueLen)); err != nil {
		_ = Close(handle)
		return fmt.Errorf("set queue length: %w", err)
	}
	if err := SetParam(handle, ParamQueueTime, uint64(h.cfg.QueueTime)); err != nil {
		_ = Close(handle)
		return fmt.Errorf("set queue time: %w", err)
	}
	if err := SetParam(handle, ParamQueueSize, uint64(h.cfg.QueueSize)); err != nil {
		_ = Close(handle)
		return fmt.Errorf("set queue size: %w", err)
	}

	h.handle = handle
	h.closed.Store(false)
	if h.cfg.InterceptDNS {
		go func() {
			_, _ = FlushDNSCache()
		}()
	}
	return nil
}

// Start opens the WinDivert handle and configures queue parameters.
func (h *Harness) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.startLocked()
}

// Pause temporarily halts WinDivert packet interception, closes the active driver handle,
// and commands the Windows Service Control Manager to stop the WinDivert driver service.
// This activates Anti-Cheat Safe Mode so EAC/BattlEye games can launch without closing the app.
func (h *Harness) Pause() error {
	h.pauseMu.Lock()
	defer h.pauseMu.Unlock()

	if h.paused.Load() {
		return nil
	}

	h.paused.Store(true)

	h.mu.Lock()
	if h.handle != InvalidHandle {
		_ = Close(h.handle)
		h.handle = InvalidHandle
	}
	h.mu.Unlock()

	_ = StopDriverService()
	return nil
}

// Resume restarts WinDivert packet interception, re-opening the kernel handle and
// restoring active desync processing.
func (h *Harness) Resume() error {
	h.pauseMu.Lock()
	defer h.pauseMu.Unlock()

	if !h.paused.Load() {
		return nil
	}

	h.mu.Lock()
	if err := h.startLocked(); err != nil {
		h.mu.Unlock()
		return fmt.Errorf("resume WinDivert handle: %w", err)
	}
	h.mu.Unlock()

	h.paused.Store(false)

	select {
	case h.resumeCh <- struct{}{}:
	default:
	}

	return nil
}

// IsPaused returns true if the harness is currently paused in Anti-Cheat Safe Mode.
func (h *Harness) IsPaused() bool {
	return h.paused.Load()
}

// Run executes the live packet reception and processing loop until ctx is cancelled or Close is called.
func (h *Harness) Run(ctx context.Context) error {
	if h.Handle() == InvalidHandle && !h.IsPaused() {
		if err := h.Start(); err != nil {
			return err
		}
	}

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = h.Close()
		case <-stopCh:
		}
	}()
	defer close(stopCh)

	// Pre-allocated 64 KiB buffer per refinement 2
	packetBuf := make([]byte, MaxPacketBufferSize)
	var addr Address

	if h.cfg.Logger != nil {
		h.cfg.Logger.Info("WinDivert packet processing loop started", "filter", h.cfg.Filter, "priority", h.cfg.Priority)
	} else {
		slog.Info("WinDivert packet processing loop started", "filter", h.cfg.Filter, "priority", h.cfg.Priority)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if h.IsPaused() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-h.resumeCh:
				// Resumed; loop around to acquire fresh handle
			}
		}

		handle := h.Handle()
		if handle == InvalidHandle {
			if h.IsPaused() {
				continue
			}
			if h.closed.Load() {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		n, err := Recv(handle, packetBuf, &addr)
		if err != nil {
			if h.IsPaused() {
				// Handle unblocked due to Pause(); loop around and wait on resumeCh
				continue
			}
			if h.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("WinDivertRecv: %w", err)
		}

		packet := packetBuf[:n]
		var sender PacketSender = liveSender{handle: handle, mu: &h.sendMu}
		if h.cfg.Sender != nil {
			sender = h.cfg.Sender
		}

		if err := h.HandlePacket(packet, &addr, sender); err != nil {
			if h.closed.Load() || h.IsPaused() || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("WinDivert live processing: %w", err)
		}
	}
}

// Close closes the open WinDivert handle and unblocks active callers.
func (h *Harness) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}

	h.pauseMu.Lock()
	h.paused.Store(false)
	select {
	case h.resumeCh <- struct{}{}:
	default:
	}
	h.pauseMu.Unlock()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.handle != InvalidHandle {
		err := Close(h.handle)
		h.handle = InvalidHandle
		return err
	}
	return nil
}

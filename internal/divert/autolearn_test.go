package divert

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestExtractIPv4TCPFlowKey(t *testing.T) {
	// Valid IPv4 TCP packet
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[9] = 6    // TCP
	copy(pkt[12:16], []byte{192, 168, 1, 50})
	copy(pkt[16:20], []byte{1, 1, 1, 1})
	// TCP header: bytes 20..40
	pkt[20] = 0xD4 // SrcPort = 54321
	pkt[21] = 0x31
	pkt[22] = 0x01 // DstPort = 443
	pkt[23] = 0xBB
	pkt[24] = 0x00 // SeqNum = 0x00010203
	pkt[25] = 0x01
	pkt[26] = 0x02
	pkt[27] = 0x03

	key, ok := ExtractIPv4TCPFlowKey(pkt)
	if !ok {
		t.Fatal("expected ok = true for valid IPv4 TCP packet")
	}
	if key.SrcIP != [4]byte{192, 168, 1, 50} {
		t.Errorf("SrcIP = %v, want 192.168.1.50", key.SrcIP)
	}
	if key.DstIP != [4]byte{1, 1, 1, 1} {
		t.Errorf("DstIP = %v, want 1.1.1.1", key.DstIP)
	}
	if key.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", key.SrcPort)
	}
	if key.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", key.DstPort)
	}
	if key.SeqNum != 0x00010203 {
		t.Errorf("SeqNum = 0x%08X, want 0x00010203", key.SeqNum)
	}

	// Invalid short packet
	_, okShort := ExtractIPv4TCPFlowKey([]byte{0x45, 0x00})
	if okShort {
		t.Error("expected ok = false for short packet")
	}

	// Invalid IHL (< 5, e.g. 4 => 16 bytes, malformed IPv4)
	pktBadIHL := make([]byte, 40)
	copy(pktBadIHL, pkt)
	pktBadIHL[0] = 0x44 // IHL = 4
	_, okBadIHL := ExtractIPv4TCPFlowKey(pktBadIHL)
	if okBadIHL {
		t.Error("expected ok = false for packet with IHL < 5")
	}

	// Non-IPv4 packet (IPv6 = 6)
	pktIPv6 := make([]byte, 40)
	copy(pktIPv6, pkt)
	pktIPv6[0] = 0x60
	_, okIPv6 := ExtractIPv4TCPFlowKey(pktIPv6)
	if okIPv6 {
		t.Error("expected ok = false for IPv6 packet")
	}

	// Non-TCP packet (UDP = 17)
	pktUDP := make([]byte, 40)
	copy(pktUDP, pkt)
	pktUDP[9] = 17
	_, okUDP := ExtractIPv4TCPFlowKey(pktUDP)
	if okUDP {
		t.Error("expected ok = false for UDP packet")
	}
}

func TestAutoLearner_EscalationLadder(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "autolearn.json")

	al := NewAutoLearner(jsonPath, true)
	simTime := time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time { return simTime })

	key := FlowKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		DstIP:   [4]byte{104, 16, 240, 1},
		SrcPort: 50000,
		DstPort: 443,
		SeqNum:  1000,
	}
	sni := "updates.discord.com"
	defStrat := StageStrategy(0)

	// Attempt 0: First transmission
	strat0, retrans0, esc0 := al.EvaluateFlow(key, sni, defStrat)
	if retrans0 || esc0 {
		t.Fatalf("attempt 0: unexpected retransmitted=%v, escalated=%v", retrans0, esc0)
	}
	if strat0.Stage != 0 || strat0.FakeTTL != 4 || strat0.SplitOffset != "sni-mid" {
		t.Fatalf("attempt 0 strategy mismatch: %+v", strat0)
	}

	// Duplicate arrival < 100ms (too fast; ignore)
	simTime = simTime.Add(50 * time.Millisecond)
	stratFast, retransFast, escFast := al.EvaluateFlow(key, sni, defStrat)
	if retransFast || escFast {
		t.Fatalf("fast packet (<100ms): unexpected retransmitted=%v, escalated=%v", retransFast, escFast)
	}
	if stratFast.Stage != 0 {
		t.Fatalf("fast packet (<100ms) stage changed: %+v", stratFast)
	}

	// Attempt 1: 1st Retransmission detected (1000ms later) -> Stage 1 (TTL 3, sni-mid)
	simTime = simTime.Add(1000 * time.Millisecond)
	strat1, retrans1, esc1 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans1 || !esc1 {
		t.Fatalf("attempt 1: expected retransmission and escalation, got retrans=%v, esc=%v", retrans1, esc1)
	}
	if strat1.Stage != 1 || strat1.FakeTTL != 3 || strat1.SplitOffset != "sni-mid" || strat1.FakeMode != "ttl" {
		t.Fatalf("attempt 1 strategy mismatch: %+v", strat1)
	}

	// Attempt 2: 2nd Retransmission detected (1200ms later) -> Stage 2 (TTL 5, sni-end, delay 2ms)
	simTime = simTime.Add(1200 * time.Millisecond)
	strat2, retrans2, esc2 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans2 || !esc2 {
		t.Fatalf("attempt 2: expected retransmission and escalation, got retrans=%v, esc=%v", retrans2, esc2)
	}
	if strat2.Stage != 2 || strat2.FakeTTL != 5 || strat2.SplitOffset != "sni-end" || strat2.DelayMS != 2 {
		t.Fatalf("attempt 2 strategy mismatch: %+v", strat2)
	}

	// Attempt 3+: 3rd Retransmission detected (1500ms later) -> Stage 3 (fake_mode=none, split=sni-mid)
	simTime = simTime.Add(1500 * time.Millisecond)
	strat3, retrans3, esc3 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans3 || !esc3 {
		t.Fatalf("attempt 3: expected retransmission and escalation, got retrans=%v, esc=%v", retrans3, esc3)
	}
	if strat3.Stage != 3 || strat3.FakeMode != "none" || strat3.SplitOffset != "sni-mid" {
		t.Fatalf("attempt 3 strategy mismatch: %+v", strat3)
	}

	// Check metrics
	retransCount, escCount, domainsLearned := al.Stats()
	if retransCount != 3 {
		t.Errorf("Retransmissions = %d, want 3", retransCount)
	}
	if escCount != 3 {
		t.Errorf("Escalations = %d, want 3", escCount)
	}
	if domainsLearned != 1 {
		t.Errorf("DomainsLearned = %d, want 1", domainsLearned)
	}

	// Verify persistence: subsequent new connection to the same domain remembers Stage 3!
	key2 := FlowKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		DstIP:   [4]byte{104, 16, 240, 1},
		SrcPort: 50002, // Different client port
		DstPort: 443,
		SeqNum:  99999, // Different seq num
	}
	stratNewConn, retransNew, escNew := al.EvaluateFlow(key2, sni, defStrat)
	if retransNew || escNew {
		t.Fatalf("new connection: unexpected retransmitted=%v, escalated=%v", retransNew, escNew)
	}
	if stratNewConn.Stage != 3 || stratNewConn.FakeMode != "none" || stratNewConn.SplitOffset != "sni-mid" {
		t.Fatalf("new connection should remember learned Stage 3: %+v", stratNewConn)
	}

	// Reload from JSON file into a new AutoLearner instance
	alReloaded := NewAutoLearner(jsonPath, true)
	if alReloaded.DomainCount() != 1 {
		t.Fatalf("reloaded AutoLearner has %d domains, want 1", alReloaded.DomainCount())
	}
	reloadedStrat, ok := alReloaded.GetLearnedDomain(sni)
	if !ok {
		t.Fatalf("reloaded AutoLearner missing domain %q", sni)
	}
	if reloadedStrat.Stage != 3 {
		t.Fatalf("reloaded strategy stage = %d, want 3", reloadedStrat.Stage)
	}
}

func TestAutoLearner_BoundedFlowEntries(t *testing.T) {
	al := NewAutoLearner("", false)
	now := time.Now()
	al.SetNowFunc(func() time.Time { return now })

	defStrat := StageStrategy(0)

	// Insert 4100 entries to test capacity capping at MaxActiveFlowEntries (4096)
	for i := 0; i < 4100; i++ {
		key := FlowKey{
			SrcIP:   [4]byte{10, 0, byte(i >> 8), byte(i)},
			DstIP:   [4]byte{1, 1, 1, 1},
			SrcPort: uint16(10000 + i%1000),
			DstPort: 443,
			SeqNum:  uint32(i * 100),
		}
		al.EvaluateFlow(key, fmt.Sprintf("domain-%d.example", i), defStrat)
	}

	al.mu.RLock()
	flowCount := len(al.flows)
	al.mu.RUnlock()

	if flowCount > MaxActiveFlowEntries {
		t.Fatalf("flowCount = %d exceeds MaxActiveFlowEntries (%d)", flowCount, MaxActiveFlowEntries)
	}
}

func TestAutoLearner_WindowExpiration(t *testing.T) {
	al := NewAutoLearner("", false)
	simTime := time.Date(2026, 10, 14, 21, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time { return simTime })

	key := FlowKey{
		SrcIP:   [4]byte{192, 168, 1, 10},
		DstIP:   [4]byte{93, 184, 216, 34},
		SrcPort: 45000,
		DstPort: 443,
		SeqNum:  500,
	}
	sni := "expired.example"
	defStrat := StageStrategy(0)

	// Attempt 0
	al.EvaluateFlow(key, sni, defStrat)

	// Packet arrives after 5000ms (> MaxRetransmissionDelay 4000ms)
	simTime = simTime.Add(5000 * time.Millisecond)
	strat, retrans, esc := al.EvaluateFlow(key, sni, defStrat)
	if retrans || esc {
		t.Fatalf("arrival after 5s should reset window; got retrans=%v, esc=%v", retrans, esc)
	}
	if strat.Stage != 0 {
		t.Fatalf("expected Stage 0 on reset; got %d", strat.Stage)
	}
}

func TestAutoLearner_Concurrency(t *testing.T) {
	al := NewAutoLearner("", false)
	defStrat := StageStrategy(0)

	var wg sync.WaitGroup
	for worker := 0; worker < 20; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				key := FlowKey{
					SrcIP:   [4]byte{10, 0, byte(w), byte(i)},
					DstIP:   [4]byte{1, 1, 1, 1},
					SrcPort: uint16(30000 + w*100 + i),
					DstPort: 443,
					SeqNum:  uint32(i),
				}
				sni := fmt.Sprintf("worker-%d.example.com", w)
				al.EvaluateFlow(key, sni, defStrat)
				_ = al.ListLearnedDomains()
			}
		}(worker)
	}
	wg.Wait()
}

func TestAutoLearner_EscalationFromLearnedStage(t *testing.T) {
	al := NewAutoLearner("", false)
	simTime := time.Date(2026, 10, 14, 22, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time { return simTime })

	sni := "prelearned.example.com"
	// Pre-seed domain at Stage 1
	al.domains[sni] = StageStrategy(1)
	al.domainsAutoLearned.Store(1)

	key := FlowKey{
		SrcIP:   [4]byte{192, 168, 1, 20},
		DstIP:   [4]byte{140, 82, 114, 4},
		SrcPort: 52000,
		DstPort: 443,
		SeqNum:  12345,
	}
	defStrat := StageStrategy(0)

	// Attempt 0: First transmission on fresh flow -> uses pre-learned Stage 1
	strat0, retrans0, esc0 := al.EvaluateFlow(key, sni, defStrat)
	if retrans0 || esc0 {
		t.Fatalf("attempt 0: unexpected retransmitted=%v, escalated=%v", retrans0, esc0)
	}
	if strat0.Stage != 1 {
		t.Fatalf("attempt 0: expected Stage 1, got %d", strat0.Stage)
	}

	// Retry 1: Retransmission at +500ms -> MUST escalate to Stage 2 (NOT stay at Stage 1 or jump to 3)
	simTime = simTime.Add(500 * time.Millisecond)
	strat1, retrans1, esc1 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans1 || !esc1 {
		t.Fatalf("retry 1: expected retransmitted=true, escalated=true, got retrans=%v, esc=%v", retrans1, esc1)
	}
	if strat1.Stage != 2 {
		t.Fatalf("retry 1: expected Stage 2, got %d", strat1.Stage)
	}

	// Retry 2: Retransmission at +1000ms -> MUST escalate to Stage 3 (NOT stay at Stage 2!)
	simTime = simTime.Add(500 * time.Millisecond)
	strat2, retrans2, esc2 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans2 || !esc2 {
		t.Fatalf("retry 2: expected retransmitted=true, escalated=true, got retrans=%v, esc=%v", retrans2, esc2)
	}
	if strat2.Stage != 3 {
		t.Fatalf("retry 2: expected Stage 3, got %d", strat2.Stage)
	}

	// Retry 3: Retransmission at +1500ms -> remains Stage 3, escalated=false (already at max stage)
	simTime = simTime.Add(500 * time.Millisecond)
	strat3, retrans3, esc3 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans3 {
		t.Fatalf("retry 3: expected retransmitted=true, got %v", retrans3)
	}
	if esc3 {
		t.Fatalf("retry 3: already at Stage 3, escalated should be false, got true")
	}
	if strat3.Stage != 3 {
		t.Fatalf("retry 3: expected Stage 3, got %d", strat3.Stage)
	}
}

func TestAutoLearner_SaveInvalidPath(t *testing.T) {
	// Attempt saving to an impossible path
	al := NewAutoLearner(filepath.Join(t.TempDir(), "non-existent-dir\x00invalid", "autolearn.json"), true)
	err := al.Save()
	if err == nil {
		t.Error("expected error saving to invalid path, got nil")
	}
}

func TestAutoLearner_ExplicitCLIFlagPriority(t *testing.T) {
	al := NewAutoLearner("", false)
	sni := "updates.discord.com"

	// Pre-seed domain at Stage 3 with fake_mode: "none" (corrupted/poisoned state)
	al.domains[sni] = LearnedDomain{
		Domain:      sni,
		Stage:       3,
		FakeMode:    "none",
		FakeTTL:     0,
		SplitOffset: "sni-mid",
		DelayMS:     0,
	}
	al.domainsAutoLearned.Store(1)

	key := FlowKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		DstIP:   [4]byte{104, 16, 240, 1},
		SrcPort: 54321,
		DstPort: 443,
		SeqNum:  1000,
	}

	// 1. With defStrat.Explicit = true (explicit CLI flags passed, e.g. --fake-mode ttl --fake-ttl 5):
	// Pre-existing autolearn must NOT override Attempt 0!
	defStratExplicit := LearnedDomain{
		Stage:       0,
		FakeMode:    "ttl",
		FakeTTL:     5,
		SplitOffset: "sni-mid",
		DelayMS:     0,
		Explicit:    true,
	}

	simTime := time.Date(2026, 10, 14, 21, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time { return simTime })

	strat, retrans, esc := al.EvaluateFlow(key, sni, defStratExplicit)
	if retrans || esc {
		t.Fatalf("attempt 0: unexpected retrans=%v, esc=%v", retrans, esc)
	}
	if strat.FakeMode != "ttl" || strat.FakeTTL != 5 {
		t.Fatalf("attempt 0 with Explicit=true must use defStrat (--fake-mode ttl, --fake-ttl 5); got FakeMode=%s, FakeTTL=%d", strat.FakeMode, strat.FakeTTL)
	}

	// Retransmission with Explicit=true must escalate to Stage 1 (and esc must be true)
	simTime = simTime.Add(500 * time.Millisecond)
	stratRetrans, retransFlag, escFlag := al.EvaluateFlow(key, sni, defStratExplicit)
	if !retransFlag {
		t.Fatalf("expected retransFlag=true, got %v", retransFlag)
	}
	if !escFlag {
		t.Fatalf("expected escFlag=true with Explicit=true, got %v", escFlag)
	}
	if stratRetrans.Stage != 1 {
		t.Fatalf("expected escalation to Stage 1, got %d", stratRetrans.Stage)
	}

	// 2. With defStrat.Explicit = false (no CLI overrides; normal autolearn resume):
	// Pre-existing learned strategy is loaded as expected.
	sni2 := "nonexplicit.discord.com"
	al.domains[sni2] = LearnedDomain{
		Domain:      sni2,
		Stage:       3,
		FakeMode:    "none",
		FakeTTL:     0,
		SplitOffset: "sni-mid",
		DelayMS:     0,
	}
	key2 := FlowKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		DstIP:   [4]byte{104, 16, 240, 1},
		SrcPort: 54322,
		DstPort: 443,
		SeqNum:  2000,
	}
	defStratNonExplicit := LearnedDomain{
		Stage:       0,
		FakeMode:    "ttl",
		FakeTTL:     5,
		SplitOffset: "sni-mid",
		DelayMS:     0,
		Explicit:    false,
	}
	stratNonExp, _, _ := al.EvaluateFlow(key2, sni2, defStratNonExplicit)
	if stratNonExp.FakeMode != "none" || stratNonExp.Stage != 3 {
		t.Fatalf("attempt 0 with Explicit=false should use learned Stage 3; got FakeMode=%s, Stage=%d", stratNonExp.FakeMode, stratNonExp.Stage)
	}
}

func TestAutoLearner_DoNotPersistUnverifiedPastStage3(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "autolearn.json")

	al := NewAutoLearner(jsonPath, true)
	simTime := time.Date(2026, 10, 14, 21, 0, 0, 0, time.UTC)
	al.SetNowFunc(func() time.Time { return simTime })

	key := FlowKey{
		SrcIP:   [4]byte{10, 0, 0, 2},
		DstIP:   [4]byte{104, 16, 240, 2},
		SrcPort: 60000,
		DstPort: 443,
		SeqNum:  1000,
	}
	sni := "failing.blocked.site"
	defStrat := StageStrategy(0)

	// Attempt 0: First transmission
	al.EvaluateFlow(key, sni, defStrat)

	// Attempt 1: 1st retransmission -> Stage 1
	simTime = simTime.Add(500 * time.Millisecond)
	al.EvaluateFlow(key, sni, defStrat)

	// Attempt 2: 2nd retransmission -> Stage 2
	simTime = simTime.Add(500 * time.Millisecond)
	al.EvaluateFlow(key, sni, defStrat)

	// Attempt 3: 3rd retransmission -> Stage 3
	simTime = simTime.Add(500 * time.Millisecond)
	strat3, _, esc3 := al.EvaluateFlow(key, sni, defStrat)
	if !esc3 || strat3.Stage != 3 {
		t.Fatalf("attempt 3: expected Stage 3 escalation, got stage=%d, esc=%v", strat3.Stage, esc3)
	}

	// Verify domain is recorded at Stage 3
	if al.DomainCount() != 1 {
		t.Fatalf("expected 1 learned domain at Stage 3, got %d", al.DomainCount())
	}

	// Attempt 4: 4th retransmission (retransmitting past Stage 3 without stabilizing)
	simTime = simTime.Add(500 * time.Millisecond)
	strat4, retrans4, esc4 := al.EvaluateFlow(key, sni, defStrat)
	if !retrans4 {
		t.Fatalf("attempt 4: expected retransmitted=true, got %v", retrans4)
	}
	if esc4 {
		t.Fatalf("attempt 4: escalated must be false past Stage 3, got true")
	}
	if strat4.Stage != 3 {
		t.Fatalf("attempt 4: expected Stage 3 fallback, got %d", strat4.Stage)
	}

	// CRITICAL: Unverified final-stage failure must NOT be kept in memory or on disk!
	if al.DomainCount() != 0 {
		t.Fatalf("domain must be purged after retransmitting past Stage 3 without stabilizing; got %d domains", al.DomainCount())
	}

	// Check reloaded state from disk
	alReloaded := NewAutoLearner(jsonPath, true)
	if alReloaded.DomainCount() != 0 {
		t.Fatalf("persisted autolearn.json must NOT contain unverified failure; got %d domains", alReloaded.DomainCount())
	}
}

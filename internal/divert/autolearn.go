package divert

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Constants governing the TCP flow tracker and escalation window.
const (
	MaxActiveFlowEntries   = 4096
	MinRetransmissionDelay = 100 * time.Millisecond
	MaxRetransmissionDelay = 4000 * time.Millisecond
	FlowEntryExpiration    = 10 * time.Second
)

// FlowKey uniquely identifies a unidirectional TCP flow segment by its 4-tuple and sequence number.
type FlowKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	SeqNum  uint32
}

// ExtractIPv4TCPFlowKey extracts the 4-tuple and sequence number from an IPv4 TCP packet.
func ExtractIPv4TCPFlowKey(packet []byte) (FlowKey, bool) {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return FlowKey{}, false
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return FlowKey{}, false
	}
	if packet[9] != 6 { // TCP
		return FlowKey{}, false
	}
	var k FlowKey
	copy(k.SrcIP[:], packet[12:16])
	copy(k.DstIP[:], packet[16:20])
	k.SrcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	k.DstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	k.SeqNum = binary.BigEndian.Uint32(packet[ihl+4 : ihl+8])
	return k, true
}

// LearnedDomain represents a persistent bypass strategy configuration for a target domain.
type LearnedDomain struct {
	Domain      string `json:"domain,omitempty"`
	Stage       int    `json:"stage"` // 1, 2, 3
	FakeMode    string `json:"fake_mode"`
	FakeTTL     uint8  `json:"fake_ttl"`
	SplitOffset string `json:"split_offset"`
	DelayMS     int    `json:"delay_ms"`
	Explicit    bool   `json:"-"`
}

// StrategyName returns a human-readable description of the evasion strategy.
func (d LearnedDomain) StrategyName() string {
	switch d.Stage {
	case 0:
		return "Stage 0 (TTL 3 + sni-mid)"
	case 1:
		return "Stage 1 (TTL 5 + sni-mid)"
	case 2:
		return "Stage 2 (TTL 4 + sni-end + 2ms delay)"
	case 3:
		return "Stage 3 (Pure OOO Split sni-mid, No Fake)"
	default:
		return fmt.Sprintf("Stage %d", d.Stage)
	}
}

// StageStrategy returns the canonical strategy parameters for an escalation ladder stage.
func StageStrategy(stage int) LearnedDomain {
	switch stage {
	case 1:
		return LearnedDomain{
			Stage:       1,
			FakeMode:    "ttl",
			FakeTTL:     3,
			SplitOffset: "sni-mid",
			DelayMS:     0,
		}
	case 2:
		return LearnedDomain{
			Stage:       2,
			FakeMode:    "ttl",
			FakeTTL:     5,
			SplitOffset: "sni-end",
			DelayMS:     2,
		}
	case 3:
		return LearnedDomain{
			Stage:       3,
			FakeMode:    "none",
			FakeTTL:     0,
			SplitOffset: "sni-mid",
			DelayMS:     0,
		}
	default:
		return LearnedDomain{
			Stage:       0,
			FakeMode:    "ttl",
			FakeTTL:     4,
			SplitOffset: "sni-mid",
			DelayMS:     0,
		}
	}
}

// flowEntry tracks the arrival history and retry state for an individual TCP flow.
type flowEntry struct {
	firstSeen  time.Time
	lastSeen   time.Time
	retryCount int
	sni        string
	baseStage  int
}

// autoLearnPersistData models the on-disk JSON structure for autolearn.json.
type autoLearnPersistData struct {
	Version   int                      `json:"version"`
	UpdatedAt string                   `json:"updated_at"`
	Domains   map[string]LearnedDomain `json:"domains"`
}

// AutoLearner tracks active TCP flows, detects retransmission blocks, escalates evasion strategies,
// and persists winning domain profiles.
type AutoLearner struct {
	mu          sync.RWMutex
	flows       map[FlowKey]*flowEntry
	domains     map[string]LearnedDomain
	persistPath string
	persistOn   bool
	nowFunc     func() time.Time

	retransmissionsDetected atomic.Uint64
	strategyEscalations     atomic.Uint64
	domainsAutoLearned      atomic.Uint64
}

// NewAutoLearner creates a new concurrency-safe AutoLearner instance.
func NewAutoLearner(persistPath string, persistOn bool) *AutoLearner {
	if persistPath == "" {
		persistPath = "autolearn.json"
	}
	al := &AutoLearner{
		flows:       make(map[FlowKey]*flowEntry),
		domains:     make(map[string]LearnedDomain),
		persistPath: persistPath,
		persistOn:   persistOn,
		nowFunc:     time.Now,
	}
	if persistOn {
		_ = al.Load()
	}
	return al
}

// SetNowFunc overrides the time source (used for deterministic testing).
func (a *AutoLearner) SetNowFunc(fn func() time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nowFunc = fn
}

// Enabled reports whether persistent auto-learning is enabled.
func (a *AutoLearner) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.persistOn
}

// DomainCount returns the number of domains with learned profiles.
func (a *AutoLearner) DomainCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.domains)
}

// ListLearnedDomains returns a sorted snapshot of all learned domain strategies.
func (a *AutoLearner) ListLearnedDomains() []LearnedDomain {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]LearnedDomain, 0, len(a.domains))
	for _, d := range a.domains {
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

// GetLearnedDomain returns the learned strategy for a domain, if any.
func (a *AutoLearner) GetLearnedDomain(domain string) (LearnedDomain, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	d, ok := a.domains[strings.ToLower(strings.TrimSpace(domain))]
	return d, ok
}

// Stats returns atomic metrics for the auto-learner.
func (a *AutoLearner) Stats() (retransmissions, escalations, domainsLearned uint64) {
	return a.retransmissionsDetected.Load(),
		a.strategyEscalations.Load(),
		a.domainsAutoLearned.Load()
}

// FlowAttempt returns the retry attempt number for a given TCP flow key.
func (a *AutoLearner) FlowAttempt(key FlowKey) int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if entry, ok := a.flows[key]; ok {
		return entry.retryCount
	}
	return 0
}

// EvaluateFlow inspects a candidate packet's flow key and SNI/host.
// It detects retransmissions within 100ms-4000ms and escalates the strategy according to the ladder.
func (a *AutoLearner) EvaluateFlow(key FlowKey, sni string, defStrat LearnedDomain) (strat LearnedDomain, retransmitted bool, escalated bool) {
	normalizedSNI := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))
	if normalizedSNI == "" {
		return defStrat, false, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.nowFunc()
	entry, exists := a.flows[key]

	if !exists || now.Sub(entry.lastSeen) > FlowEntryExpiration {
		// Attempt 0: First transmission
		a.evictLocked(now)

		// Check if domain already has a learned strategy
		learned, hasLearned := a.domains[normalizedSNI]
		baseStage := 0
		if hasLearned && !defStrat.Explicit {
			strat = learned
			baseStage = learned.Stage
		} else {
			strat = defStrat
			baseStage = defStrat.Stage
		}
		strat.Domain = normalizedSNI

		a.flows[key] = &flowEntry{
			firstSeen:  now,
			lastSeen:   now,
			retryCount: 0,
			sni:        normalizedSNI,
			baseStage:  baseStage,
		}
		return strat, false, false
	}

	elapsed := now.Sub(entry.lastSeen)

	// If arrival is too fast (< 100ms), do not treat as retransmission
	if elapsed < MinRetransmissionDelay {
		if entry.retryCount > 0 {
			stage := entry.baseStage + entry.retryCount
			if stage > 3 {
				stage = 3
			}
			curr := StageStrategy(stage)
			curr.Domain = normalizedSNI
			return curr, false, false
		}
		if learned, hasLearned := a.domains[normalizedSNI]; hasLearned && !defStrat.Explicit {
			return learned, false, false
		}
		return defStrat, false, false
	}

	// If elapsed exceeds retransmission window (> 4000ms), reset entry
	if elapsed > MaxRetransmissionDelay {
		entry.firstSeen = now
		entry.lastSeen = now
		entry.retryCount = 0
		if learned, hasLearned := a.domains[normalizedSNI]; hasLearned && !defStrat.Explicit {
			return learned, false, false
		}
		return defStrat, false, false
	}

	// Retransmission detected within 100ms - 4000ms window!
	entry.retryCount++
	entry.lastSeen = now
	retransmitted = true
	a.retransmissionsDetected.Add(1)

	if entry.baseStage+entry.retryCount > 3 {
		// Retransmission past Stage 3 without stabilizing:
		// Do not persist unverified final-stage failure.
		if _, existed := a.domains[normalizedSNI]; existed {
			delete(a.domains, normalizedSNI)
			a.domainsAutoLearned.Store(uint64(len(a.domains)))
			if a.persistOn && a.persistPath != "" {
				_ = a.saveLocked()
			}
		}
		fallbackStrat := StageStrategy(3)
		fallbackStrat.Domain = normalizedSNI
		return fallbackStrat, true, false
	}

	// Escalation Ladder:
	// Attempt 0: Stage 0 (ttl=3, split=sni-mid)
	// Attempt 1: Stage 1 (ttl=5, split=sni-mid)
	// Attempt 2: Stage 2 (ttl=4, split=sni-end, delay=2ms)
	// Attempt 3+: Stage 3 (fake_mode=none, split=sni-mid)
	stage := entry.baseStage + entry.retryCount
	if stage > 3 {
		stage = 3
	}

	newStrat := StageStrategy(stage)
	newStrat.Domain = normalizedSNI

	prevStrat, alreadyLearned := a.domains[normalizedSNI]
	if !alreadyLearned || newStrat.Stage > prevStrat.Stage || defStrat.Explicit {
		escalated = true
		a.strategyEscalations.Add(1)
	}

	a.domains[normalizedSNI] = newStrat
	if !alreadyLearned {
		a.domainsAutoLearned.Add(1)
	}

	if escalated && a.persistOn && a.persistPath != "" {
		_ = a.saveLocked()
	}

	return newStrat, retransmitted, escalated
}

// evictLocked prunes expired or oldest flow entries to maintain bounds.
func (a *AutoLearner) evictLocked(now time.Time) {
	if len(a.flows) < MaxActiveFlowEntries {
		return
	}

	// 1. Purge expired entries
	for k, e := range a.flows {
		if now.Sub(e.lastSeen) > FlowEntryExpiration {
			delete(a.flows, k)
		}
	}

	// 2. If still at or over capacity, evict oldest entries
	for len(a.flows) >= MaxActiveFlowEntries {
		var oldestKey FlowKey
		var oldestTime time.Time
		first := true
		for k, e := range a.flows {
			if first || e.lastSeen.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.lastSeen
				first = false
			}
		}
		if first {
			break
		}
		delete(a.flows, oldestKey)
	}
}

// Load reads and parses domain profiles from persistPath.
func (a *AutoLearner) Load() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := os.ReadFile(a.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read autolearn file: %w", err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}

	// 1. Try wrapped format: {"version": 1, "domains": {...}}
	var wrap autoLearnPersistData
	if err := json.Unmarshal(data, &wrap); err == nil && wrap.Domains != nil {
		for domain, strat := range wrap.Domains {
			d := strings.ToLower(strings.TrimSpace(domain))
			strat.Domain = d
			a.domains[d] = strat
		}
		a.domainsAutoLearned.Store(uint64(len(a.domains)))
		return nil
	}

	// 2. Fallback to direct map format: {"domain": {...}}
	var direct map[string]LearnedDomain
	if err := json.Unmarshal(data, &direct); err == nil {
		for domain, strat := range direct {
			d := strings.ToLower(strings.TrimSpace(domain))
			strat.Domain = d
			a.domains[d] = strat
		}
		a.domainsAutoLearned.Store(uint64(len(a.domains)))
		return nil
	}

	return fmt.Errorf("invalid autolearn JSON format")
}

// Save writes current domain strategies to disk atomically.
func (a *AutoLearner) Save() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.saveLocked()
}

func (a *AutoLearner) saveLocked() error {
	if a.persistPath == "" {
		return nil
	}

	wrap := autoLearnPersistData{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Domains:   a.domains,
	}

	bytesData, err := json.MarshalIndent(wrap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal autolearn data: %w", err)
	}

	dir := filepath.Dir(a.persistPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	tmpFile := fmt.Sprintf("%s.%d.tmp", a.persistPath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, bytesData, 0644); err != nil {
		return fmt.Errorf("write temp autolearn file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		_ = os.Remove(a.persistPath)
		if err := os.Rename(tmpFile, a.persistPath); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(10 * time.Millisecond)
		}
	}

	return fmt.Errorf("rename autolearn file after 3 attempts: %w", lastErr)
}

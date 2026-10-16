package webui

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed dashboard.html
var dashboardHTML []byte

// WebUIStats holds serializable counters for the web dashboard.
type WebUIStats struct {
	PacketsRecv                uint64 `json:"packets_recv"`
	PacketsSent                uint64 `json:"packets_sent"`
	QUICDropped                uint64 `json:"quic_dropped"`
	TCPFastPath                uint64 `json:"tcp_fast_path"`
	TCPCandidate               uint64 `json:"tcp_candidate"`
	CandidateHandshakes        uint64 `json:"candidate_handshakes"`
	PacketsSplit               uint64 `json:"packets_split"`
	OutOfOrderSegmentsInjected uint64 `json:"out_of_order_injected"`
	PassThroughFallbacks       uint64 `json:"fallbacks"`
	SendErrors                 uint64 `json:"send_errors"`
	FakePacketsInjected        uint64 `json:"fake_packets_injected"`
	FakeTTLCount               uint64 `json:"fake_ttl_count"`
	FakeBadChecksumCount       uint64 `json:"fake_bad_checksum_count"`
	DNSQueriesIntercepted      uint64 `json:"dns_intercepted"`
	DNSQueriesResolvedDoH      uint64 `json:"dns_resolved_doh"`
	DNSFallbacks               uint64 `json:"dns_fallbacks"`

	// Milestone 2.7 Adaptive Retransmission & Auto-Learner metrics:
	RetransmissionsDetected uint64 `json:"retransmissions_detected"`
	StrategyEscalations     uint64 `json:"strategy_escalations"`
	DomainsAutoLearned      uint64 `json:"domains_auto_learned"`

	// Milestone 2.8 Sinkhole Guard & Packet 2 Desync metrics:
	SinkholeBlocks      uint64 `json:"sinkhole_blocks"`
	DNSFlushesTriggered uint64 `json:"dns_flushes_triggered"`
	Packet2Desynced     uint64 `json:"packet2_desynced"`
}

// LearnedDomainInfo models a learned domain strategy for the WebUI dashboard.
type LearnedDomainInfo struct {
	Domain      string `json:"domain"`
	Stage       int    `json:"stage"`
	Strategy    string `json:"strategy"`
	FakeMode    string `json:"fake_mode"`
	FakeTTL     uint8  `json:"fake_ttl"`
	SplitOffset string `json:"split_offset"`
	DelayMS     int    `json:"delay_ms"`
}

// EngineController abstracts engine state queries and Anti-Cheat Safe Mode toggle.
type EngineController interface {
	Mode() string
	Strategy() string
	DriverState() string
	IsPaused() bool
	Pause() error
	Resume() error
	Stats() WebUIStats
	LearnedDomains() []LearnedDomainInfo
}

// Server provides the loopback-only HTTP monitoring and control interface.
type Server struct {
	bindAddr   string
	controller EngineController
	logger     *slog.Logger
	server     *http.Server
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
}

// NewServer constructs and validates an embedded WebUI server instance.
// It strictly validates that bindAddr binds exclusively to loopback (127.0.0.1).
func NewServer(bindAddr string, controller EngineController, logger *slog.Logger) (*Server, error) {
	if controller == nil {
		return nil, errors.New("controller cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid webui bind address format %q: %w", bindAddr, err)
	}

	// Strictly enforce loopback address per Section 10.2
	if host != "127.0.0.1" && host != "localhost" {
		return nil, fmt.Errorf("webui binding %q rejected; must be strictly loopback (127.0.0.1) for security", host)
	}

	s := &Server{
		bindAddr:   bindAddr,
		controller: controller,
		logger:     logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/driver/pause", s.handlePause)
	mux.HandleFunc("/api/driver/resume", s.handleResume)

	// Wrap mux in security middleware (DNS-rebinding prevention, CSRF protection, headers)
	handler := s.securityMiddleware(mux)

	s.server = &http.Server{
		Addr:              bindAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	return s, nil
}

// securityMiddleware enforces loopback Host validation, Origin/Referer CSRF defense, and secure HTTP headers.
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. DNS-Rebinding Protection: Validate Host header
		host := r.Host
		if strings.Contains(host, ":") {
			h, _, err := net.SplitHostPort(host)
			if err == nil {
				host = h
			}
		}
		if host != "127.0.0.1" && host != "localhost" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden: Invalid Host header for loopback WebUI\n"))
			return
		}

		// 2. CSRF Defense for State-Changing Requests (POST/PUT/DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, err := url.Parse(origin)
				if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("Forbidden: Cross-origin state modification rejected\n"))
					return
				}
			} else {
				referer := r.Header.Get("Referer")
				if referer != "" {
					u, err := url.Parse(referer)
					if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
						w.Header().Set("Content-Type", "text/plain; charset=utf-8")
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte("Forbidden: Cross-origin state modification rejected\n"))
						return
					}
				}
			}

			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Forbidden: Cross-site request rejected\n"))
				return
			}
		}

		// 3. Security Headers
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
		w.Header().Set("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dashboardHTML)
}

type statsResponse struct {
	Mode           string              `json:"mode"`
	DriverState    string              `json:"driver_state"`
	IsPaused       bool                `json:"is_paused"`
	Strategy       string              `json:"strategy"`
	Stats          WebUIStats          `json:"stats"`
	LearnedDomains []LearnedDomainInfo `json:"learned_domains"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	learned := s.controller.LearnedDomains()
	if learned == nil {
		learned = []LearnedDomainInfo{}
	}

	resp := statsResponse{
		Mode:           s.controller.Mode(),
		DriverState:    s.controller.DriverState(),
		IsPaused:       s.controller.IsPaused(),
		Strategy:       s.controller.Strategy(),
		Stats:          s.controller.Stats(),
		LearnedDomains: learned,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

type driverActionResponse struct {
	Status      string `json:"status"`
	DriverState string `json:"driver_state"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed; POST required", http.StatusMethodNotAllowed)
		return
	}

	err := s.controller.Pause()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(driverActionResponse{
			Status:      "error",
			DriverState: s.controller.DriverState(),
			Error:       err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(driverActionResponse{
		Status:      "paused",
		DriverState: s.controller.DriverState(),
	})
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed; POST required", http.StatusMethodNotAllowed)
		return
	}

	err := s.controller.Resume()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(driverActionResponse{
			Status:      "error",
			DriverState: s.controller.DriverState(),
			Error:       err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(driverActionResponse{
		Status:      "running",
		DriverState: s.controller.DriverState(),
	})
}

// Start binds to the configured loopback address and serves requests.
func (s *Server) Start() error {
	s.mu.Lock()
	ln, err := net.Listen("tcp", s.bindAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("listen on %s: %w", s.bindAddr, err)
	}
	s.listener = ln
	s.mu.Unlock()

	s.logger.Info("embedded webui dashboard started", "addr", fmt.Sprintf("http://%s", ln.Addr().String()))
	err = s.server.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Addr returns the bound network address of the WebUI server.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.bindAddr
}

// Shutdown gracefully stops the WebUI HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

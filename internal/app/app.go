package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dpibypass/internal/config"
	"dpibypass/internal/dnsdoh"
	"dpibypass/internal/proxy"
)

const defaultShutdownGracePeriod = 5 * time.Second

type trackedConn struct {
	conn   net.Conn
	cancel context.CancelFunc
}

// App manages the lifecycle of the local dpibypass proxy.
type App struct {
	cfg          *config.Config
	logger       *slog.Logger
	dialer       proxy.Dialer
	listener     net.Listener
	mu           sync.Mutex
	running      atomic.Bool
	active       atomic.Int64
	shutdownSig  chan struct{}
	shutdownOnce sync.Once
	connsMu      sync.Mutex
	conns        map[uint64]trackedConn
	nextConnID   uint64
	closed       chan struct{}
}

// New constructs an App instance with configuration and structured logger.
func New(cfg *config.Config, logger *slog.Logger) (*App, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &App{
		cfg:         cfg,
		logger:      logger,
		shutdownSig: make(chan struct{}),
		closed:      make(chan struct{}),
		conns:       make(map[uint64]trackedConn),
	}, nil
}

// SetDialer allows injecting a custom Dialer (useful for testing with mock targets).
func (a *App) SetDialer(d proxy.Dialer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dialer = d
}

// ActiveConnections returns the number of currently active proxy connections.
func (a *App) ActiveConnections() int64 {
	return a.active.Load()
}

// Addr returns the network address the App's listener is bound to, or empty if not yet listening.
func (a *App) Addr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

func (a *App) initiateShutdown() {
	a.shutdownOnce.Do(func() {
		close(a.shutdownSig)
		a.mu.Lock()
		ln := a.listener
		a.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	})
}

func (a *App) cancelRemainingConns() {
	a.connsMu.Lock()
	defer a.connsMu.Unlock()
	for _, tc := range a.conns {
		tc.cancel()
		_ = tc.conn.Close()
	}
}

// Shutdown initiates graceful shutdown of the application, stopping new connections
// and waiting for active connections to finish or until ctx expires.
// If ctx expires before connections finish, remaining connections are forcefully closed.
func (a *App) Shutdown(ctx context.Context) error {
	if !a.running.Load() {
		return nil
	}

	a.initiateShutdown()

	select {
	case <-a.closed:
		return nil
	case <-ctx.Done():
		a.cancelRemainingConns()
		<-a.closed
		return ctx.Err()
	}
}

// Run starts the loopback listener and blocks until ctx is cancelled or Shutdown is invoked.
// When shutdown begins, it immediately stops accepting new connections, drains existing
// connections up to the configured or default grace period, and forcefully terminates
// any lingering connections if the grace deadline expires.
func (a *App) Run(ctx context.Context) error {
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("app is already running")
	}
	defer a.running.Store(false)
	defer close(a.closed)

	ln, err := proxy.ListenLoopback(a.cfg.Listen)
	if err != nil {
		return fmt.Errorf("start listener: %w", err)
	}

	a.mu.Lock()
	a.listener = ln
	dialer := a.dialer
	a.mu.Unlock()

	if dialer == nil {
		dialTimeout := time.Duration(a.cfg.Timeouts.DialMS) * time.Millisecond
		base := &proxy.NetDialer{
			Timeout: dialTimeout,
		}
		if a.cfg.DoH.Enabled {
			res, err := dnsdoh.NewResolver(a.cfg.DoH, a.logger)
			if err != nil {
				_ = ln.Close()
				return fmt.Errorf("initialize DoH resolver: %w", err)
			}
			dialer = proxy.NewResolvingDialer(base, res, dialTimeout)
		} else {
			dialer = base
		}
	}

	boundAddr := ln.Addr().String()
	a.logger.Info("dpibypass proxy listener started",
		slog.String("address", boundAddr),
		slog.String("default_profile", a.cfg.DefaultProfile),
		slog.Int("max_connections", a.cfg.Limits.MaxConnections),
	)

	stopMonitor := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			a.logger.Info("shutdown signal received; stopping listener")
			a.initiateShutdown()
		case <-a.shutdownSig:
		case <-stopMonitor:
		}
	}()
	defer close(stopMonitor)

	matcher, err := config.NewDomainMatcher(a.cfg.DomainRules)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("compile domain rules: %w", err)
	}

	defaultProf := a.cfg.Profiles[a.cfg.DefaultProfile]
	handlerCfg := proxy.HandlerConfig{
		DialTimeout:              time.Duration(a.cfg.Timeouts.DialMS) * time.Millisecond,
		IdleTimeout:              time.Duration(a.cfg.Timeouts.IdleS) * time.Second,
		InitialInspectionTimeout: time.Duration(a.cfg.Timeouts.InitialInspectionMS) * time.Millisecond,
		MaxInitialBytes:          a.cfg.Limits.MaxInitialBytes,
		DefaultProfile:           defaultProf,
		Profiles:                 a.cfg.Profiles,
		Matcher:                  matcher,
	}

	var wg sync.WaitGroup

acceptLoop:
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-a.shutdownSig:
				break acceptLoop
			default:
				if errors.Is(err, net.ErrClosed) {
					break acceptLoop
				}
				a.logger.Error("accept error", slog.String("error", err.Error()))
				return fmt.Errorf("accept: %w", err)
			}
		}

		select {
		case <-a.shutdownSig:
			_ = conn.Close()
			break acceptLoop
		default:
		}

		current := a.active.Add(1)
		if current > int64(a.cfg.Limits.MaxConnections) {
			a.active.Add(-1)
			a.logger.Warn("connection rejected: max connection limit reached",
				slog.Int("limit", a.cfg.Limits.MaxConnections),
			)
			_ = conn.Close()
			continue
		}

		connCtx, connCancel := context.WithCancel(context.Background())
		a.connsMu.Lock()
		connID := a.nextConnID
		a.nextConnID++
		a.conns[connID] = trackedConn{conn: conn, cancel: connCancel}
		a.connsMu.Unlock()

		wg.Add(1)
		go func(c net.Conn, id uint64, cCtx context.Context, cCancel context.CancelFunc) {
			defer wg.Done()
			defer a.active.Add(-1)
			defer func() {
				a.connsMu.Lock()
				delete(a.conns, id)
				a.connsMu.Unlock()
				cCancel()
			}()

			if err := proxy.ServeConn(cCtx, c, dialer, a.logger, handlerCfg); err != nil {
				a.logger.Debug("proxy connection finished",
					slog.String("error_category", proxy.ClassifyError(err)),
				)
			}
		}(conn, connID, connCtx, connCancel)
	}

	a.mu.Lock()
	a.listener = nil
	a.mu.Unlock()

	graceDuration := defaultShutdownGracePeriod
	if a.cfg.Timeouts.ShutdownGraceMS > 0 {
		graceDuration = time.Duration(a.cfg.Timeouts.ShutdownGraceMS) * time.Millisecond
	}

	a.logger.Info("draining active connections",
		slog.Int64("active", a.active.Load()),
		slog.Duration("grace_period", graceDuration),
	)

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	drainTimer := time.NewTimer(graceDuration)
	defer drainTimer.Stop()

	select {
	case <-doneCh:
		a.logger.Info("listener shut down gracefully; all connections drained cleanly")
	case <-drainTimer.C:
		a.logger.Warn("shutdown grace period expired; forcefully terminating active connections",
			slog.Int64("remaining", a.active.Load()),
		)
		a.cancelRemainingConns()
		<-doneCh
		a.logger.Info("listener shut down gracefully after terminating remaining connections")
	}

	return nil
}

//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// setupShutdownContext returns a context canceled upon receiving SIGINT or SIGTERM on non-Windows systems.
func setupShutdownContext(cleanupFn func()) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	var once sync.Once
	runCleanup := func() {
		once.Do(func() {
			cancel()
			if cleanupFn != nil {
				cleanupFn()
			}
		})
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			runCleanup()
		case <-ctx.Done():
		}
	}()

	shutdown := func() {
		signal.Stop(sigCh)
		runCleanup()
	}

	return ctx, shutdown
}

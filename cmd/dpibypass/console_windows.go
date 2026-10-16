//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	kernel32DLL               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCtrlHandler = kernel32DLL.NewProc("SetConsoleCtrlHandler")
)

const (
	ctrlCEvent        = 0
	ctrlBreakEvent    = 1
	ctrlCloseEvent    = 2
	ctrlLogoffEvent   = 5
	ctrlShutdownEvent = 6
)

// setupShutdownContext returns a context canceled upon receiving Ctrl+C, Ctrl+Break,
// console window close, user logoff, or system shutdown. It also invokes cleanupFn
// synchronously when a console close or shutdown event occurs, giving the process
// time to clean up hosts entries and unload drivers before termination.
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

	handler := syscall.NewCallback(func(ctrlType uint32) uintptr {
		switch ctrlType {
		case ctrlCEvent, ctrlBreakEvent, ctrlCloseEvent, ctrlLogoffEvent, ctrlShutdownEvent:
			runCleanup()
			// Return 1 (TRUE) so Windows waits for cleanup to finish before terminating
			return 1
		default:
			return 0
		}
	})

	r, _, _ := procSetConsoleCtrlHandler.Call(handler, 1)

	shutdown := func() {
		signal.Stop(sigCh)
		if r != 0 {
			_, _, _ = procSetConsoleCtrlHandler.Call(handler, 0)
		}
		runCleanup()
	}

	return ctx, shutdown
}

//go:build windows && amd64

package divert

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Handle represents an open WinDivert handle.
type Handle uintptr

// InvalidHandle represents the WinDivert INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1).
const InvalidHandle Handle = ^Handle(0)

var (
	// Lazy DLL resolution ensures that compiling, importing, or testing this package
	// does NOT load WinDivert.dll or touch the file system/driver stack.
	modWinDivert = syscall.NewLazyDLL("WinDivert.dll")

	procWinDivertOpen     = modWinDivert.NewProc("WinDivertOpen")
	procWinDivertRecv     = modWinDivert.NewProc("WinDivertRecv")
	procWinDivertSend     = modWinDivert.NewProc("WinDivertSend")
	procWinDivertClose    = modWinDivert.NewProc("WinDivertClose")
	procWinDivertSetParam = modWinDivert.NewProc("WinDivertSetParam")
)

var (
	modKernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleW    = modKernel32.NewProc("GetModuleHandleW")
	procGetCurrentProcess   = modKernel32.NewProc("GetCurrentProcess")
	modAdvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken    = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")
)

// IsDLLLoaded reports whether WinDivert.dll is currently loaded into the process's address space.
// It uses GetModuleHandleW, which queries the PEB module list and NEVER loads the DLL from disk.
func IsDLLLoaded() bool {
	namePtr, err := syscall.UTF16PtrFromString("WinDivert.dll")
	if err != nil {
		return false
	}
	r0, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))
	return r0 != 0
}

// Open opens a new WinDivert handle.
//
// In Phase 2.1A, live handle opening is strictly prohibited. This function is provided
// solely as dynamic binding scaffolding for future authorized milestones.
func Open(filter string, layer uint32, priority int16, flags uint64) (Handle, error) {
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return InvalidHandle, fmt.Errorf("invalid filter string: %w", err)
	}

	r0, _, callErr := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	h := Handle(r0)
	if h == InvalidHandle {
		if callErr != nil && callErr != syscall.Errno(0) {
			return InvalidHandle, callErr
		}
		return InvalidHandle, errors.New("WinDivertOpen failed (INVALID_HANDLE_VALUE)")
	}
	return h, nil
}

// Recv receives a packet from an open WinDivert handle.
func Recv(h Handle, packet []byte, addr *Address) (int, error) {
	if h == InvalidHandle {
		return 0, errors.New("cannot receive from InvalidHandle")
	}
	if len(packet) == 0 {
		return 0, errors.New("packet receive buffer cannot be empty")
	}

	var recvLen uint32
	var addrPtr uintptr
	if addr != nil {
		addrPtr = uintptr(unsafe.Pointer(addr))
	}

	r0, _, callErr := procWinDivertRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(&recvLen)),
		addrPtr,
	)
	if r0 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WinDivertRecv failed")
	}
	return int(recvLen), nil
}

// Send injects a packet to an open WinDivert handle.
func Send(h Handle, packet []byte, addr *Address) (int, error) {
	if h == InvalidHandle {
		return 0, errors.New("cannot send to InvalidHandle")
	}
	if len(packet) == 0 {
		return 0, errors.New("packet send buffer cannot be empty")
	}
	if addr == nil {
		return 0, errors.New("address metadata is required for WinDivertSend")
	}

	var sendLen uint32
	r0, _, callErr := procWinDivertSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r0 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WinDivertSend failed")
	}
	return int(sendLen), nil
}

// Close closes an open WinDivert handle.
func Close(h Handle) error {
	if h == InvalidHandle {
		return nil
	}
	r0, _, callErr := procWinDivertClose.Call(uintptr(h))
	if r0 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("WinDivertClose failed")
	}
	return nil
}

// SetParam sets a WinDivert parameter (such as ParamQueueLength, ParamQueueTime, or ParamQueueSize).
func SetParam(h Handle, param uint32, value uint64) error {
	if h == InvalidHandle {
		return errors.New("cannot set parameter on InvalidHandle")
	}
	r0, _, callErr := procWinDivertSetParam.Call(
		uintptr(h),
		uintptr(param),
		uintptr(value),
	)
	if r0 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("WinDivertSetParam failed")
	}
	return nil
}

// IsAvailable reports whether WinDivert.dll can be located and loaded into memory.
// If not already loaded, it attempts a transient LoadLibrary / FreeLibrary probe.
func IsAvailable() bool {
	if IsDLLLoaded() {
		return true
	}
	h, err := syscall.LoadLibrary("WinDivert.dll")
	if err != nil {
		return false
	}
	_ = syscall.FreeLibrary(h)
	return true
}

// IsElevated reports whether the current process token possesses administrative elevation.
func IsElevated() (bool, error) {
	curProc, _, _ := procGetCurrentProcess.Call()
	var token syscall.Handle
	// TOKEN_QUERY = 0x0008
	r0, _, err := procOpenProcessToken.Call(curProc, uintptr(0x0008), uintptr(unsafe.Pointer(&token)))
	if r0 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return false, fmt.Errorf("OpenProcessToken: %w", err)
		}
		return false, errors.New("OpenProcessToken failed")
	}
	defer syscall.CloseHandle(token)

	// TokenElevation = 20
	var elevation uint32
	var retLen uint32
	r0, _, err = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(20), // TokenElevation
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r0 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return false, fmt.Errorf("GetTokenInformation: %w", err)
		}
		return false, errors.New("GetTokenInformation failed")
	}
	return elevation != 0, nil
}

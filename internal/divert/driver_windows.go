//go:build windows && amd64

package divert

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// WinDivert known service names registered by WinDivert.dll.
var knownDriverServiceNames = []string{"WinDivert", "WinDivert14"}

// Service Control Manager access rights and control codes.
const (
	scManagerConnect   = 0x0001
	serviceQueryStatus = 0x0004
	serviceStop        = 0x0020
	serviceControlStop = 0x00000001

	serviceStopped         = 0x00000001
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004
	serviceContinuePending = 0x00000005
	servicePausePending    = 0x00000006
	servicePaused          = 0x00000007
)

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

var (
	procOpenSCManagerW     = modAdvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW       = modAdvapi32.NewProc("OpenServiceW")
	procQueryServiceStatus = modAdvapi32.NewProc("QueryServiceStatus")
	procControlService     = modAdvapi32.NewProc("ControlService")
	procCloseServiceHandle = modAdvapi32.NewProc("CloseServiceHandle")
)

// DriverStatus encapsulates the current operating environment and WinDivert kernel driver state.
type DriverStatus struct {
	Supported    bool   `json:"supported"`
	Elevated     bool   `json:"elevated"`
	DLLAvailable bool   `json:"dll_available"`
	ServiceFound bool   `json:"service_found"`
	ServiceName  string `json:"service_name"`
	ServiceState string `json:"service_state"`
	IsRunning    bool   `json:"is_running"`
}

// QueryDriverStatus inspects the host environment, checking elevation, WinDivert DLL presence,
// and querying the Windows Service Control Manager strictly for the WinDivert driver service state.
func QueryDriverStatus() DriverStatus {
	elevated, _ := IsElevated()
	dllAvailable := IsAvailable()

	st := DriverStatus{
		Supported:    true,
		Elevated:     elevated,
		DLLAvailable: dllAvailable,
		ServiceFound: false,
		ServiceName:  "WinDivert",
		ServiceState: "NOT_INSTALLED",
		IsRunning:    false,
	}

	// Open Service Control Manager with read-only connect rights
	scm, _, err := procOpenSCManagerW.Call(0, 0, uintptr(scManagerConnect))
	if scm == 0 {
		if err != nil && err != syscall.Errno(0) {
			st.ServiceState = fmt.Sprintf("SCM_QUERY_ERROR (%v)", err)
		} else {
			st.ServiceState = "SCM_QUERY_ERROR"
		}
		return st
	}
	defer procCloseServiceHandle.Call(scm)

	for _, sName := range knownDriverServiceNames {
		namePtr, err := syscall.UTF16PtrFromString(sName)
		if err != nil {
			continue
		}

		svc, _, _ := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(namePtr)), uintptr(serviceQueryStatus))
		if svc != 0 {
			var sStatus serviceStatus
			r0, _, _ := procQueryServiceStatus.Call(svc, uintptr(unsafe.Pointer(&sStatus)))
			procCloseServiceHandle.Call(svc)

			if r0 != 0 {
				st.ServiceFound = true
				st.ServiceName = sName
				st.ServiceState = serviceStateToString(sStatus.currentState)
				st.IsRunning = (sStatus.currentState == serviceRunning)
				return st
			}
		}
	}

	return st
}

// StopDriverService safely commands the WinDivert driver service to stop if it is currently running.
// It strictly scopes operations to WinDivert services and never alters unrelated Windows services.
func StopDriverService() error {
	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("check elevation: %w", err)
	}
	if !elevated {
		return errors.New("administrative privileges required to stop WinDivert driver service; please run as Administrator")
	}

	scm, _, callErr := procOpenSCManagerW.Call(0, 0, uintptr(scManagerConnect))
	if scm == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return fmt.Errorf("open SCM: %w", callErr)
		}
		return errors.New("open SCM failed")
	}
	defer procCloseServiceHandle.Call(scm)

	var lastErr error
	stoppedAny := false

	for _, sName := range knownDriverServiceNames {
		namePtr, err := syscall.UTF16PtrFromString(sName)
		if err != nil {
			continue
		}

		svc, _, _ := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(namePtr)), uintptr(serviceStop|serviceQueryStatus))
		if svc == 0 {
			continue
		}

		var sStatus serviceStatus
		r0, _, _ := procQueryServiceStatus.Call(svc, uintptr(unsafe.Pointer(&sStatus)))
		if r0 != 0 && sStatus.currentState == serviceRunning {
			var stopStatus serviceStatus
			r0, _, stopErr := procControlService.Call(svc, uintptr(serviceControlStop), uintptr(unsafe.Pointer(&stopStatus)))
			if r0 == 0 {
				if stopErr != nil && stopErr != syscall.Errno(0) {
					lastErr = fmt.Errorf("stop %s service: %w", sName, stopErr)
				} else {
					lastErr = fmt.Errorf("stop %s service failed", sName)
				}
			} else {
				stoppedAny = true
			}
		}
		procCloseServiceHandle.Call(svc)
	}

	if lastErr != nil && !stoppedAny {
		return lastErr
	}
	return nil
}

func serviceStateToString(state uint32) string {
	switch state {
	case serviceStopped:
		return "STOPPED"
	case serviceStartPending:
		return "START_PENDING"
	case serviceStopPending:
		return "STOP_PENDING"
	case serviceRunning:
		return "RUNNING"
	case serviceContinuePending:
		return "CONTINUE_PENDING"
	case servicePausePending:
		return "PAUSE_PENDING"
	case servicePaused:
		return "PAUSED"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", state)
	}
}

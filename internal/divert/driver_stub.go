//go:build !windows || !amd64

package divert

import "errors"

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

// QueryDriverStatus returns an unsupported status on non-Windows/non-amd64 platforms.
func QueryDriverStatus() DriverStatus {
	return DriverStatus{
		Supported:    false,
		Elevated:     false,
		DLLAvailable: false,
		ServiceFound: false,
		ServiceName:  "WinDivert",
		ServiceState: "NOT_SUPPORTED",
		IsRunning:    false,
	}
}

// StopDriverService returns an error on non-Windows/non-amd64 platforms.
func StopDriverService() error {
	return errors.New("WinDivert driver service management is only supported on Windows amd64")
}

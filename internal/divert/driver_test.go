package divert

import (
	"runtime"
	"testing"
)

func TestQueryDriverStatus(t *testing.T) {
	st := QueryDriverStatus()
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		if !st.Supported {
			t.Fatal("expected Supported to be true on windows/amd64")
		}
		// In un-elevated test mode, SCM query returns status without crashing
		if st.ServiceState == "" {
			t.Fatal("expected non-empty ServiceState")
		}
	} else {
		if st.Supported {
			t.Fatal("expected Supported to be false on non-windows/non-amd64")
		}
		if st.ServiceState != "NOT_SUPPORTED" {
			t.Fatalf("expected ServiceState 'NOT_SUPPORTED', got %q", st.ServiceState)
		}
	}
}

func TestStopDriverService_UnElevatedSafeRejection(t *testing.T) {
	elevated, _ := IsElevated()
	if !elevated {
		err := StopDriverService()
		if err == nil {
			t.Fatal("expected error when un-elevated user attempts StopDriverService")
		}
	}
}

//go:build !windows

package sysproxy

const (
	DefaultInternetSettingsSubkey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	REG_NONE                      = 0
	REG_SZ                        = 1
	REG_EXPAND_SZ                 = 2
	REG_BINARY                    = 3
	REG_DWORD                     = 4
)

// WindowsStore stub for non-Windows platforms.
type WindowsStore struct {
	Subkey string
}

func NewWindowsStore(subkey string) *WindowsStore {
	if subkey == "" {
		subkey = DefaultInternetSettingsSubkey
	}
	return &WindowsStore{Subkey: subkey}
}

func (s *WindowsStore) ReadValue(name string) (RegistryValue, error) {
	return RegistryValue{}, ErrUnsupportedPlatform
}

func (s *WindowsStore) WriteValue(name string, valType uint32, data []byte) error {
	return ErrUnsupportedPlatform
}

func (s *WindowsStore) DeleteValue(name string) error {
	return ErrUnsupportedPlatform
}

func (s *WindowsStore) DeleteSubkey() error {
	return ErrUnsupportedPlatform
}

func (s *WindowsStore) NotifyWinINet() error {
	return ErrUnsupportedPlatform
}

//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// DefaultInternetSettingsSubkey is the standard per-user registry path for Windows Internet Settings.
	DefaultInternetSettingsSubkey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	// Microsoft WinINet option constants.
	// INTERNET_OPTION_REFRESH = 37 causes WinINet to reread proxy settings from the registry.
	// INTERNET_OPTION_SETTINGS_CHANGED = 39 notifies the system that registry proxy settings have changed.
	INTERNET_OPTION_REFRESH          = 37
	INTERNET_OPTION_SETTINGS_CHANGED = 39

	// Windows Registry Value Types.
	REG_NONE      = 0
	REG_SZ        = 1
	REG_EXPAND_SZ = 2
	REG_BINARY    = 3
	REG_DWORD     = 4
)

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modWininet  = syscall.NewLazyDLL("wininet.dll")

	procRegOpenKeyExW    = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW  = modAdvapi32.NewProc("RegCreateKeyExW")
	procRegQueryValueExW = modAdvapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW   = modAdvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW  = modAdvapi32.NewProc("RegDeleteValueW")
	procRegDeleteKeyW    = modAdvapi32.NewProc("RegDeleteKeyW")
	procRegCloseKey      = modAdvapi32.NewProc("RegCloseKey")

	procInternetSetOptionW = modWininet.NewProc("InternetSetOptionW")
)

// WindowsStore implements Store using direct Windows registry syscalls under HKEY_CURRENT_USER
// and the WinINet InternetSetOptionW notification API.
type WindowsStore struct {
	Subkey string
}

// NewWindowsStore creates a WindowsStore targeting the specified subkey.
// If subkey is empty, it defaults to DefaultInternetSettingsSubkey.
func NewWindowsStore(subkey string) *WindowsStore {
	if subkey == "" {
		subkey = DefaultInternetSettingsSubkey
	}
	return &WindowsStore{Subkey: subkey}
}

func (s *WindowsStore) openKey(access uint32) (syscall.Handle, error) {
	subkeyPtr, err := syscall.UTF16PtrFromString(s.Subkey)
	if err != nil {
		return 0, err
	}
	var hKey syscall.Handle
	r1, _, _ := procRegOpenKeyExW.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		uintptr(access),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return hKey, nil
}

func (s *WindowsStore) createKey(access uint32) (syscall.Handle, error) {
	subkeyPtr, err := syscall.UTF16PtrFromString(s.Subkey)
	if err != nil {
		return 0, err
	}
	var hKey syscall.Handle
	var disp uint32
	r1, _, _ := procRegCreateKeyExW.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		0,
		0,
		uintptr(access),
		0,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&disp)),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return hKey, nil
}

// ReadValue reads a raw registry value from HKCU under the configured subkey.
func (s *WindowsStore) ReadValue(name string) (RegistryValue, error) {
	hKey, err := s.openKey(syscall.KEY_QUERY_VALUE)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return RegistryValue{Exists: false}, nil
		}
		return RegistryValue{}, fmt.Errorf("open registry key: %w", err)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return RegistryValue{}, err
	}

	var valType uint32
	var dataLen uint32

	// Query buffer size required
	r1, _, _ := procRegQueryValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		0,
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r1 == uintptr(syscall.ERROR_FILE_NOT_FOUND) {
		return RegistryValue{Exists: false}, nil
	}
	if r1 != 0 {
		return RegistryValue{}, fmt.Errorf("query value %q size: %w", name, syscall.Errno(r1))
	}

	if dataLen == 0 {
		return RegistryValue{
			Exists: true,
			Type:   valType,
			Data:   []byte{},
		}, nil
	}

	buf := make([]byte, dataLen)
	r1, _, _ = procRegQueryValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r1 != 0 {
		return RegistryValue{}, fmt.Errorf("query value %q: %w", name, syscall.Errno(r1))
	}

	return RegistryValue{
		Exists: true,
		Type:   valType,
		Data:   buf[:dataLen],
	}, nil
}

// WriteValue writes a raw registry value under HKCU. If the subkey does not exist, it creates it.
func (s *WindowsStore) WriteValue(name string, valType uint32, data []byte) error {
	hKey, err := s.openKey(syscall.KEY_SET_VALUE)
	if err != nil {
		hKey, err = s.createKey(syscall.KEY_SET_VALUE)
		if err != nil {
			return fmt.Errorf("open/create registry key: %w", err)
		}
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}

	r1, _, _ := procRegSetValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(valType),
		uintptr(ptr),
		uintptr(len(data)),
	)
	if r1 != 0 {
		return fmt.Errorf("set value %q: %w", name, syscall.Errno(r1))
	}
	return nil
}

// DeleteValue removes a value under HKCU. If the key or value is missing, it returns nil.
func (s *WindowsStore) DeleteValue(name string) error {
	hKey, err := s.openKey(syscall.KEY_SET_VALUE)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("open registry key: %w", err)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	r1, _, _ := procRegDeleteValueW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(namePtr)),
	)
	if r1 == uintptr(syscall.ERROR_FILE_NOT_FOUND) || r1 == 0 {
		return nil
	}
	return fmt.Errorf("delete value %q: %w", name, syscall.Errno(r1))
}

// DeleteSubkey deletes the subkey itself under HKCU. Used primarily for test scratch cleanup.
func (s *WindowsStore) DeleteSubkey() error {
	subkeyPtr, err := syscall.UTF16PtrFromString(s.Subkey)
	if err != nil {
		return err
	}
	r1, _, _ := procRegDeleteKeyW.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subkeyPtr)),
	)
	if r1 == uintptr(syscall.ERROR_FILE_NOT_FOUND) || r1 == 0 {
		return nil
	}
	return fmt.Errorf("delete subkey %q: %w", s.Subkey, syscall.Errno(r1))
}

// NotifyWinINet broadcasts settings changes and refreshes the WinINet session cache.
func (s *WindowsStore) NotifyWinINet() error {
	var errs []error

	// 1. Notify that settings changed
	r1, _, err := procInternetSetOptionW.Call(
		0, // NULL handle applies globally to current session
		uintptr(INTERNET_OPTION_SETTINGS_CHANGED),
		0,
		0,
	)
	if r1 == 0 {
		errs = append(errs, fmt.Errorf("INTERNET_OPTION_SETTINGS_CHANGED (39) failed: %w", err))
	}

	// 2. Force WinINet to refresh its proxy cache from the registry
	r2, _, err := procInternetSetOptionW.Call(
		0,
		uintptr(INTERNET_OPTION_REFRESH),
		0,
		0,
	)
	if r2 == 0 {
		errs = append(errs, fmt.Errorf("INTERNET_OPTION_REFRESH (37) failed: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

package sysproxy

// Store abstracts read, write, delete, and notification operations on the operating system.
// Decoupling via this interface allows complete unit testing of backup lifecycle, drift detection,
// partial write rollback, and corruption handling without touching the host operating system's registry.
type Store interface {
	// ReadValue reads a registry value by name. If the value does not exist,
	// it returns a RegistryValue with Exists: false and nil error.
	ReadValue(name string) (RegistryValue, error)

	// WriteValue sets a registry value by name with the specified type and raw data bytes.
	WriteValue(name string, valType uint32, data []byte) error

	// DeleteValue removes a registry value by name. If the value does not exist,
	// it returns nil (idempotent).
	DeleteValue(name string) error

	// NotifyWinINet broadcasts setting changes and refreshes the WinINet session cache.
	NotifyWinINet() error
}

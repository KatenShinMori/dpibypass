package sysproxy

import (
	"errors"
	"time"
)

// RegistryValue captures the existence, registry type, and raw data bytes of a registry value.
// Raw byte fidelity ensures that missing values are distinguished from empty values, and
// no type conversion or encoding loss occurs.
type RegistryValue struct {
	Exists bool   `json:"exists"`
	Type   uint32 `json:"type"`           // e.g. 4 for REG_DWORD, 1 for REG_SZ
	Data   []byte `json:"data,omitempty"` // exact raw bytes
}

// Backup captures the pre-existing state and applied state of tracked settings.
type Backup struct {
	Version          int                      `json:"version"`
	Timestamp        time.Time                `json:"timestamp"`
	PID              int                      `json:"pid"`
	ConfiguredServer string                   `json:"configured_server"`
	Original         map[string]RegistryValue `json:"original"`
	Applied          map[string]RegistryValue `json:"applied"`
}

// State represents the observable lifecycle state of the Windows system proxy configuration.
type State string

const (
	StateInactiveClean        State = "INACTIVE_NO_BACKUP"
	StateActive               State = "ACTIVE"
	StateExternalModification State = "EXTERNAL_MODIFICATION"
	StateCorruptBackup        State = "CORRUPT_BACKUP"
	StateInactiveDirtyBackup  State = "INACTIVE_DIRTY_BACKUP"
)

// Status provides diagnostic details on the current registry configuration and backup state.
type Status struct {
	State              State                    `json:"state"`
	CurrentSettings    map[string]RegistryValue `json:"current_settings"`
	AutoConfigURL      string                   `json:"autoconfig_url,omitempty"`
	ProxyOverride      string                   `json:"proxy_override,omitempty"`
	Backup             *Backup                  `json:"backup,omitempty"`
	BackupPath         string                   `json:"backup_path"`
	DriftDetails       []string                 `json:"drift_details,omitempty"`
	ListenerReachable  bool                     `json:"listener_reachable"`
	ConfiguredListener string                   `json:"configured_listener"`
}

// EnableResult summarizes the outcome of activating the system proxy.
type EnableResult struct {
	ConfiguredServer    string `json:"configured_server"`
	BackupPath          string `json:"backup_path"`
	NotificationWarning string `json:"notification_warning,omitempty"`
}

// RestoreResult summarizes the outcome of restoring proxy settings.
type RestoreResult struct {
	AlreadyRestored     bool   `json:"already_restored"`
	Success             bool   `json:"success"`
	Forced              bool   `json:"forced"`
	BackupRetired       bool   `json:"backup_retired"`
	BackupPath          string `json:"backup_path"`
	NotificationWarning string `json:"notification_warning,omitempty"`
}

var (
	ErrExternalModification = errors.New("external modification detected in Windows proxy settings")
	ErrNoBackupFound        = errors.New("no backup file found")
	ErrCorruptBackup        = errors.New("backup file is corrupt or invalid")
	ErrUnreachableListener  = errors.New("local proxy listener is not reachable")
	ErrNotLoopback          = errors.New("proxy endpoint must be a loopback address")
	ErrInvalidPort          = errors.New("proxy endpoint port must be between 1 and 65535")
	ErrAutoConfigActive     = errors.New("automatic proxy configuration (AutoConfigURL) is active in Windows settings")
	ErrBackupAlreadyExists  = errors.New("active or unretired backup file already exists")
	ErrUnsupportedPlatform  = errors.New("sysproxy is only supported on Windows")
	ErrRestorationMismatch  = errors.New("restoration verification failed: registry state does not match backup")
	ErrRollbackFailed       = errors.New("activation failure rollback failed: registry state may be in an inconsistent state")
)

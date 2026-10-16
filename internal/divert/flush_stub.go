//go:build !windows

package divert

// FlushDNSCache is a no-op on non-Windows platforms.
func FlushDNSCache() ([]byte, error) {
	return nil, nil
}

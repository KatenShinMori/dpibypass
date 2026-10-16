//go:build windows

package divert

import "os/exec"

// FlushDNSCache executes 'ipconfig /flushdns' on Windows to purge cached DNS entries.
func FlushDNSCache() ([]byte, error) {
	cmd := exec.Command("ipconfig", "/flushdns")
	return cmd.CombinedOutput()
}

package scanners

import (
	"os/exec"
	"strings"
)

// CapabilityResult is exported for main.go reporting
type CapabilityResult struct {
	Path         string
	Capabilities string
	IsDangerous  bool
}

// Critical capabilities that often lead to instant privilege escalation
var DangerousCapabilities = []string{
	"cap_setuid", "cap_setgid",
	"cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
	"cap_dac_read_search", "cap_fowner", "cap_fsetid",
	"cap_sys_module", "cap_sys_boot", "cap_sys_chroot",
}

// ScanCapabilities uses the native getcap binary to rapidly scan the filesystem.
func ScanCapabilities(root string) ([]CapabilityResult, error) {
	var results []CapabilityResult

	// Run getcap recursively. This is 1000x faster than walking the FS in Go
	// and spawning a child process for every single file.
	cmd := exec.Command("getcap", "-r", root)
	
	// We ignore the error because getcap will return an error (exit status 1)
	// if it encounters 'Permission denied' on certain directories, which is expected.
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Expected format: "/usr/bin/ping cap_net_raw=ep"
		// or "/usr/bin/ping = cap_net_raw+ep"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}

		path := strings.TrimSpace(parts[0])
		caps := strings.TrimSpace(parts[1])
		
		// Clean up the formatting if it has the " = " syntax
		caps = strings.TrimPrefix(caps, "=")
		caps = strings.TrimSpace(caps)

		isDangerous := false
		capsLower := strings.ToLower(caps)
		for _, dc := range DangerousCapabilities {
			if strings.Contains(capsLower, dc) {
				isDangerous = true
				break
			}
		}

		results = append(results, CapabilityResult{
			Path:         path,
			Capabilities: caps,
			IsDangerous:  isDangerous,
		})
	}

	return results, nil
}
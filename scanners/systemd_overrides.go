package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// SystemdOverrideResult represents a misconfiguration or writable drop-in in systemd unit overrides.
type SystemdOverrideResult struct {
	Path        string `json:"path"`
	ServiceName string `json:"service_name"`
	Type        string `json:"type"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint"`
	IsDangerous bool   `json:"is_dangerous"`
}

var systemdSearchPaths = []string{
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
}

// ScanSystemdOverrides audits systemd drop-in override directories (*.service.d) for
// writable directory permissions, writable .conf files, or ExecStart overrides pointing to writable binaries.
func ScanSystemdOverrides() ([]SystemdOverrideResult, error) {
	var results []SystemdOverrideResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	for _, basePath := range systemdSearchPaths {
		entries, err := os.ReadDir(basePath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			dirName := entry.Name()
			if !strings.HasSuffix(dirName, ".service.d") && !strings.HasSuffix(dirName, ".target.d") && !strings.HasSuffix(dirName, ".socket.d") {
				continue
			}

			serviceName := strings.TrimSuffix(dirName, ".service.d")
			serviceName = strings.TrimSuffix(serviceName, ".target.d")
			serviceName = strings.TrimSuffix(serviceName, ".socket.d")

			dirPath := filepath.Join(basePath, dirName)
			dirInfo, err := entry.Info()
			if err == nil {
				uid, gid := getSyscallOwnership(dirInfo)
				mode := uint32(dirInfo.Mode().Perm())

				// 1. Check if the .d directory itself is writable by current user
				if userCtx.CanWrite(uid, gid, mode) {
					results = append(results, SystemdOverrideResult{
						Path:        dirPath,
						ServiceName: serviceName,
						Type:        "systemd_override_dir_writable",
						RiskLevel:   "CRITICAL",
						Reason:      fmt.Sprintf("Systemd override directory '%s' for service '%s' is writable by current user", dirPath, serviceName),
						ExploitHint: fmt.Sprintf("echo -e '[Service]\\nExecStart=/tmp/rootbash\\n' > %s/evil.conf && systemctl daemon-reload", dirPath),
						IsDangerous: true,
					})
				}
			}

			// 2. Audit .conf files inside the override directory
			confEntries, err := os.ReadDir(dirPath)
			if err != nil {
				continue
			}

			for _, confEntry := range confEntries {
				if confEntry.IsDir() || !strings.HasSuffix(confEntry.Name(), ".conf") {
					continue
				}

				confPath := filepath.Join(dirPath, confEntry.Name())
				confInfo, err := confEntry.Info()
				if err != nil {
					continue
				}

				uid, gid := getSyscallOwnership(confInfo)
				mode := uint32(confInfo.Mode().Perm())

				// Check if the .conf file is writable
				if userCtx.CanWrite(uid, gid, mode) {
					results = append(results, SystemdOverrideResult{
						Path:        confPath,
						ServiceName: serviceName,
						Type:        "systemd_override_conf_writable",
						RiskLevel:   "CRITICAL",
						Reason:      fmt.Sprintf("Systemd drop-in override file '%s' (service '%s') is writable by current user", confPath, serviceName),
						ExploitHint: fmt.Sprintf("echo -e '[Service]\\nExecStart=/tmp/rootshell\\n' >> %s && systemctl daemon-reload", confPath),
						IsDangerous: true,
					})
				}

				// 3. Inspect .conf file content for ExecStart / ExecStartPre / EnvironmentFile overrides
				parseConfDirectives(confPath, serviceName, userCtx, &results)
			}
		}
	}

	return results, nil
}

func parseConfDirectives(confPath string, serviceName string, userCtx *UserContext, results *[]SystemdOverrideResult) {
	file, err := os.Open(confPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "ExecStart=") || strings.HasPrefix(line, "ExecStartPre=") || strings.HasPrefix(line, "ExecStartPost=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				execCmd := strings.TrimSpace(parts[1])
				execCmd = strings.TrimPrefix(execCmd, "-") // strip systemd ignore error prefix
				fields := strings.Fields(execCmd)
				if len(fields) > 0 {
					targetBin := fields[0]
					if strings.HasPrefix(targetBin, "/") {
						if binInfo, err := os.Stat(targetBin); err == nil {
							uid, gid := getSyscallOwnership(binInfo)
							mode := uint32(binInfo.Mode().Perm())
							if userCtx.CanWrite(uid, gid, mode) {
								*results = append(*results, SystemdOverrideResult{
									Path:        targetBin,
									ServiceName: serviceName,
									Type:        "systemd_override_exec_writable",
									RiskLevel:   "CRITICAL",
									Reason:      fmt.Sprintf("Executable '%s' referenced in systemd override '%s' is writable by current user", targetBin, confPath),
									ExploitHint: fmt.Sprintf("Overwrite '%s' with payload -> root execution on service '%s' start", targetBin, serviceName),
									IsDangerous: true,
								})
							}
						}
					}
				}
			}
		}
	}
}

func getSyscallOwnership(info os.FileInfo) (int, int) {
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			return int(stat.Uid), int(stat.Gid)
		}
	}
	return 0, 0
}

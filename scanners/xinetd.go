package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// XinetdResult represents an audit finding for a vulnerable or writable xinetd service configuration or binary.
type XinetdResult struct {
	ConfigFile    string `json:"config_file"`
	ServiceName   string `json:"service_name"`
	ServerBinary  string `json:"server_binary,omitempty"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// ScanXinetd audits /etc/xinetd.d/ configuration files and target server binaries for unauthorized writability.
func ScanXinetd() ([]XinetdResult, error) {
	return scanXinetdInternal("/etc/xinetd.d")
}

func scanXinetdInternal(xinetdDir string) ([]XinetdResult, error) {
	var results []XinetdResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// 1. Early exit if directory does not exist (<0.1ms)
	dirInfo, err := os.Stat(xinetdDir)
	if err != nil || !dirInfo.IsDir() {
		return results, nil
	}

	entries, err := os.ReadDir(xinetdDir)
	if err != nil {
		return results, nil
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), "~") {
			continue
		}

		confPath := filepath.Join(xinetdDir, entry.Name())
		confInfo, err := entry.Info()
		if err != nil || !confInfo.Mode().IsRegular() {
			continue
		}

		// Check if config file is writable
		confWritable := false
		if sys := confInfo.Sys(); sys != nil {
			if stat, ok := sys.(*syscall.Stat_t); ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				mode := uint32(confInfo.Mode().Perm())
				if userCtx.UID != 0 {
					confWritable = userCtx.CanWrite(uid, gid, mode)
				} else {
					confWritable = (mode&syscall.S_IWOTH != 0) || (gid != 0 && (mode&syscall.S_IWGRP != 0))
				}
			}
		}

		// Parse the config file
		f, err := os.Open(confPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		serviceName := entry.Name()
		serverBinary := ""
		isDisabled := false

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}

			if strings.HasPrefix(line, "service ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					serviceName = parts[1]
				}
			}

			// Extract key and value split on '='
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				val := strings.TrimSpace(parts[1])
				// Strip trailing comments
				if cIdx := strings.Index(val, "#"); cIdx >= 0 {
					val = strings.TrimSpace(val[:cIdx])
				}
				if key == "disable" && strings.EqualFold(val, "yes") {
					isDisabled = true
				}
				if key == "server" && val != "" {
					serverBinary = val
				}
			}
		}
		f.Close()

		// Skip disabled services
		if isDisabled {
			continue
		}

		// Finding 1: Config file itself is writable
		if confWritable {
			results = append(results, XinetdResult{
				ConfigFile:    confPath,
				ServiceName:   serviceName,
				ServerBinary:  serverBinary,
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("xinetd service configuration file '%s' is writable by current user — attacker can modify 'server' directive to execute arbitrary root commands on network connection", confPath),
				ExploitHint:   fmt.Sprintf("sed -i 's|server.*|server = /tmp/rootshell|' %s", confPath),
				Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s", confPath, confPath),
				ComplianceTag: "Legacy-Service-Hijack",
				IsDangerous:   true,
			})
		}

		// Finding 2: Server target binary is writable
		if serverBinary != "" {
			if binInfo, bErr := os.Stat(serverBinary); bErr == nil && binInfo.Mode().IsRegular() {
				if bSys := binInfo.Sys(); bSys != nil {
					if bStat, ok := bSys.(*syscall.Stat_t); ok {
						bUID := int(bStat.Uid)
						bGID := int(bStat.Gid)
						bMode := uint32(binInfo.Mode().Perm())

						isWritable := false
						if userCtx.UID != 0 {
							isWritable = userCtx.CanWrite(bUID, bGID, bMode)
						} else {
							isWritable = (bMode&syscall.S_IWOTH != 0) || (bGID != 0 && (bMode&syscall.S_IWGRP != 0))
						}

						if isWritable {
							results = append(results, XinetdResult{
								ConfigFile:    confPath,
								ServiceName:   serviceName,
								ServerBinary:  serverBinary,
								RiskLevel:     "CRITICAL",
								Reason:        fmt.Sprintf("Target server binary '%s' configured in xinetd service '%s' is writable by current user — replacing binary achieves root execution upon service trigger", serverBinary, serviceName),
								ExploitHint:   fmt.Sprintf("cp /tmp/rootshell %s", serverBinary),
								Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", serverBinary, serverBinary),
								ComplianceTag: "Legacy-Service-Hijack",
								IsDangerous:   true,
							})
						}
					}
				}
			}
		}
	}

	return results, nil
}

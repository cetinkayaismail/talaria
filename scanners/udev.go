package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// UdevResult represents a udev rule or target binary writability finding.
type UdevResult struct {
	Path          string `json:"path"`
	RuleFile      string `json:"rule_file"`
	Directive     string `json:"directive"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var (
	udevDirs = []string{
		"/etc/udev/rules.d",
		"/run/udev/rules.d",
		"/lib/udev/rules.d",
		"/usr/lib/udev/rules.d",
	}
	runRegex     = regexp.MustCompile(`RUN(?:\+?=|=)\s*"([^"]+)"`)
	programRegex = regexp.MustCompile(`(?:PROGRAM|IMPORT\{program\})(?:\+?=|=)\s*"([^"]+)"`)
)

// ScanUdevAuditor checks udev rule files and referenced binaries for loose permissions.
func ScanUdevAuditor() ([]UdevResult, error) {
	var results []UdevResult
	userCtx := GetUserContext()
	seenFiles := make(map[string]bool)

	for _, dir := range udevDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}

			rulePath := filepath.Join(dir, entry.Name())
			if seenFiles[rulePath] {
				continue
			}
			seenFiles[rulePath] = true

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// 1. Check if the .rules file itself is writable by current user
			if sys := info.Sys(); sys != nil {
				if stat, ok := sys.(*syscall.Stat_t); ok && userCtx != nil {
					uid := int(stat.Uid)
					gid := int(stat.Gid)
					mode := uint32(info.Mode().Perm())
					if userCtx.CanWrite(uid, gid, mode) {
						results = append(results, UdevResult{
							Path:          rulePath,
							RuleFile:      rulePath,
							Directive:     "file_permissions",
							RiskLevel:     "CRITICAL",
							Reason:        fmt.Sprintf("Udev rule file '%s' is writable by current user — allows adding arbitrary 'RUN+=\"/path/payload\"' for root code execution on kernel device events", rulePath),
							ExploitHint:   fmt.Sprintf("echo 'ACTION==\"add\", SUBSYSTEM==\"net\", RUN+=\"/tmp/rootshell\"' >> %s", rulePath),
							Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s && udevadm control --reload", rulePath, rulePath),
							ComplianceTag: "CIS-Linux-1.1.23 / NIST-CM-6",
							IsDangerous:   true,
						})
					}
				}
			}

			// 2. Parse file for RUN+= and PROGRAM= directives
			parseUdevRuleFile(rulePath, userCtx, &results)
		}
	}

	return results, nil
}

func parseUdevRuleFile(rulePath string, userCtx *UserContext, results *[]UdevResult) {
	file, err := os.Open(rulePath)
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

		// Match RUN+= directives
		if matches := runRegex.FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) > 1 {
					cmdStr := strings.TrimSpace(m[1])
					checkUdevTargetExecutable(rulePath, "RUN+=", cmdStr, userCtx, results)
				}
			}
		}

		// Match PROGRAM= / IMPORT{program}= directives
		if matches := programRegex.FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) > 1 {
					cmdStr := strings.TrimSpace(m[1])
					checkUdevTargetExecutable(rulePath, "PROGRAM=", cmdStr, userCtx, results)
				}
			}
		}
	}
}

func checkUdevTargetExecutable(rulePath, directive, cmdStr string, userCtx *UserContext, results *[]UdevResult) {
	// Built-in udev actions (e.g. "socket:", "kmod") are not binary paths
	if strings.HasPrefix(cmdStr, "socket:") || strings.HasPrefix(cmdStr, "kmod") {
		return
	}

	// Extract binary executable path (first argument token)
	fields := strings.Fields(cmdStr)
	if len(fields) == 0 {
		return
	}
	binPath := fields[0]

	// Handle relative or absolute paths
	var targetPaths []string
	if strings.HasPrefix(binPath, "/") {
		targetPaths = append(targetPaths, binPath)
	} else {
		// Standard udev helper locations
		targetPaths = append(targetPaths,
			filepath.Join("/lib/udev", binPath),
			filepath.Join("/usr/lib/udev", binPath),
			filepath.Join("/etc/udev", binPath),
		)
	}

	for _, target := range targetPaths {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}

		if sys := info.Sys(); sys != nil {
			if stat, ok := sys.(*syscall.Stat_t); ok && userCtx != nil {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				mode := uint32(info.Mode().Perm())
				if userCtx.CanWrite(uid, gid, mode) {
					*results = append(*results, UdevResult{
						Path:          target,
						RuleFile:      rulePath,
						Directive:     directive,
						RiskLevel:     "CRITICAL",
						Reason:        fmt.Sprintf("Executable '%s' referenced in udev rule '%s' (%s) is writable by current user — executes as root on kernel device events", target, rulePath, directive),
						ExploitHint:   fmt.Sprintf("Overwrite '%s' with payload -> root code execution on device add/remove", target),
						Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", target, target),
						ComplianceTag: "CIS-Linux-1.1.23 / NIST-SI-7",
						IsDangerous:   true,
					})
				}
			}
		}
	}
}

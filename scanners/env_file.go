package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// EnvFileResult holds findings from the systemd EnvironmentFile scanner (A6).
//
// Attack vector: a writable EnvironmentFile referenced by a root-owned systemd
// service can be used to inject LD_PRELOAD, PATH, or arbitrary env vars that
// execute attacker-controlled code the next time the service is (re)started.
type EnvFileResult struct {
	ServiceFile   string `json:"service_file"`  // e.g. /etc/systemd/system/myapp.service
	ServiceName   string `json:"service_name"`  // e.g. myapp
	EnvFilePath   string `json:"env_file_path"` // e.g. /etc/default/myapp
	IsWritable    bool   `json:"is_writable"`
	InjectionType string `json:"injection_type"` // "LD_PRELOAD", "PATH", or "GENERIC"
	RiskLevel     string `json:"risk_level"`     // "CRITICAL" or "HIGH"
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// systemdServiceDirs holds the three canonical locations where systemd searches
// for unit files. We search all three to maximise coverage without WalkDir.
var systemdServiceDirs = []string{
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
}

// ScanSystemdEnvFiles parses all .service unit files found in the standard
// systemd search directories and reports any EnvironmentFile= references that
// are writable by the current user (A6).
func ScanSystemdEnvFiles() ([]EnvFileResult, error) {
	ctx := GetUserContext()
	var results []EnvFileResult

	// Deduplicate (ServiceFile, EnvFilePath) pairs — the same service may be
	// symlinked into multiple directories.
	seen := make(map[string]bool)

	for _, dir := range systemdServiceDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Directory may not exist on all distros — not an error.
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}

			servicePath := filepath.Join(dir, entry.Name())
			envPaths := extractEnvironmentFiles(servicePath)

			for _, envPath := range envPaths {
				key := servicePath + "|" + envPath
				if seen[key] {
					continue
				}
				seen[key] = true

				// Stat the env file — skip if it doesn't exist (dash-prefix
				// semantics: missing file is ignored at runtime too).
				info, err := os.Stat(envPath)
				if err != nil {
					continue
				}

				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}

				if !ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
					continue
				}

				// Determine injection type by reading the existing env file
				// content. Even if none of the high-impact vars are present,
				// the attacker can inject them — the type is "GENERIC" in that
				// case but still dangerous.
				injType := classifyEnvFile(envPath)

				// Risk level: /etc/default/* is often user-override territory.
				riskLevel := "CRITICAL"
				fpNote := ""
				if strings.HasPrefix(envPath, "/etc/default/") {
					riskLevel = "HIGH"
					fpNote = " (Note: /etc/default/ files are sometimes intentionally writable as user-override configs — verify this is unintentional.)"
				}

				serviceName := strings.TrimSuffix(entry.Name(), ".service")
				reason := buildEnvFileReason(servicePath, envPath, injType, fpNote)

				results = append(results, EnvFileResult{
					ServiceFile:   servicePath,
					ServiceName:   serviceName,
					EnvFilePath:   envPath,
					IsWritable:    true,
					InjectionType: injType,
					RiskLevel:     riskLevel,
					Reason:        reason,
					Remediation:   fmt.Sprintf("chown root:root %s && chmod 0640 %s", envPath, envPath),
					ComplianceTag: "CIS-Linux-5.1.9 / NIST-CM-6",
				})
			}
		}
	}

	return results, nil
}

// extractEnvironmentFiles parses a single .service file and returns all
// EnvironmentFile= paths after applying the dash-prefix and specifier rules.
//
// Systemd unit file syntax:
//
//	[Service]
//	EnvironmentFile=/etc/default/myapp
//	EnvironmentFile=-/etc/optional/override     # dash = ignore if absent
//	EnvironmentFile=/var/run/%i.env             # specifier — we skip these
func extractEnvironmentFiles(servicePath string) []string {
	f, err := os.Open(servicePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Match EnvironmentFile= (case-insensitive for robustness)
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "environmentfile=") {
			continue
		}

		val := strings.TrimSpace(line[len("EnvironmentFile="):])
		if val == "" {
			continue
		}

		// Strip dash-prefix: "-/path" → "/path"
		if strings.HasPrefix(val, "-") {
			val = val[1:]
		}

		// Skip paths with unresolvable systemd specifiers (e.g. %i, %n, %u).
		// Attempting to resolve them without the full instance context would
		// yield wrong paths and silent false negatives.
		if strings.ContainsRune(val, '%') {
			continue
		}

		// Must be an absolute path — relative paths are not valid here.
		if !strings.HasPrefix(val, "/") {
			continue
		}

		paths = append(paths, val)
	}
	return paths
}

// classifyEnvFile reads the existing content of an env file and returns the
// most dangerous injection type that an attacker could add or already has.
//
// We scan for LD_PRELOAD and PATH because these have direct code-execution
// impact. Any other writable env file defaults to "GENERIC" — still dangerous
// because the attacker controls environment variables seen by a root process.
func classifyEnvFile(envPath string) string {
	f, err := os.Open(envPath)
	if err != nil {
		// Can't read content — file is writable but unreadable.
		// Still flag as GENERIC (attacker can write even if we can't read).
		return "GENERIC"
	}
	defer f.Close()

	hasLDPreload := false
	hasPATH := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "LD_PRELOAD=") {
			hasLDPreload = true
		}
		if strings.HasPrefix(upper, "PATH=") {
			hasPATH = true
		}
	}

	switch {
	case hasLDPreload:
		return "LD_PRELOAD"
	case hasPATH:
		return "PATH"
	default:
		return "GENERIC"
	}
}

// buildEnvFileReason produces the human-readable reason string for a finding.
func buildEnvFileReason(servicePath, envPath, injType, fpNote string) string {
	var sb strings.Builder
	sb.WriteString("EnvironmentFile '")
	sb.WriteString(envPath)
	sb.WriteString("' referenced by systemd service '")
	sb.WriteString(servicePath)
	sb.WriteString("' is writable by the current user. ")

	switch injType {
	case "LD_PRELOAD":
		sb.WriteString("The file already contains LD_PRELOAD= — modify it to point to a malicious shared library that executes as root on service restart.")
	case "PATH":
		sb.WriteString("The file already contains PATH= — modify it to prepend a writable directory with a malicious binary that executes as root on service restart.")
	default:
		sb.WriteString("Inject 'LD_PRELOAD=/tmp/evil.so' or 'PATH=/tmp:$PATH' into this file to execute arbitrary code as root the next time the service is restarted.")
	}

	sb.WriteString(fpNote)
	return sb.String()
}

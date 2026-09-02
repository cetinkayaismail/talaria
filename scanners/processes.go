package scanners

import (
	"bufio"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessResult stores information about discovered processes
type ProcessResult struct {
	PID         int
	User        string
	UID         int
	Command     string
	IsDangerous bool
	EnvSecrets  []string
}

// CriticalProcesses: Debug tools and network shells that indicate active exploitation
var CriticalProcesses = []string{
	"gdb", "strace", "ltrace", "lldb", // Debuggers - real-time process inspection
	"nc", "ncat", "netcat", // Raw network shells commonly used in exploits
}

// SuspiciousProcesses: Processes that may indicate background activity there might be some sneaky things going on.
var SuspiciousProcesses = []string{
	"telnet", "wget", "curl",
}

// getSystemUserShells parses /etc/passwd and returns a map of UID -> default shell
func getSystemUserShells() map[int]string {
	shells := make(map[int]string)
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return shells
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Split(trimmed, ":")
		if len(parts) >= 7 {
			uid, err := strconv.Atoi(parts[2])
			if err == nil {
				shells[uid] = parts[6]
			}
		}
	}
	return shells
}

// ScanProcesses enumerates the /proc filesystem to find high-value targets
func ScanProcesses() ([]ProcessResult, error) {
	var results []ProcessResult

	// Get current user context to filter out own processes
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)
	userShells := getSystemUserShells()

	// Open /proc directory
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// PIDs are always numeric directory names
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		// Read process UID from /proc/[pid]/status
		uid, err := getProcessUID(entry)
		if err != nil {
			continue
		}

		// Skip processes owned by the current user to reduce noise
		if uid == currentUID {
			continue
		}

		// Read full command line from /proc/[pid]/cmdline
		cmdline, err := getProcessCmdline(entry)
		if err != nil || cmdline == "" {
			continue
		}

		// Identify if the process is a potential PrivEsc vector
		userName := lookupUsername(uid)
		isDangerous := checkProcessDanger(cmdline, uid, userShells)

		// Read environment variables for exposed secrets
		envSecrets, _ := getProcessEnviron(entry)
		if len(envSecrets) > 0 {
			isDangerous = true
		}

		results = append(results, ProcessResult{
			PID:         pid,
			User:        userName,
			UID:         uid,
			Command:     cmdline,
			IsDangerous: isDangerous,
			EnvSecrets:  envSecrets,
		})
	}

	return results, nil
}

// getProcessUID parses the status file for the effective UID
func getProcessUID(pid string) (int, error) {
	file, err := os.Open(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return 0, err
	}
	defer file.Close() // Manual close within function scope

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, io.EOF
}

// getProcessCmdline reads the command line arguments
func getProcessCmdline(pid string) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return "", err
	}
	// cmdline arguments are null-byte separated
	cmd := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmd), nil
}

// lookupUsername converts UID to a human-readable name
func lookupUsername(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return "unknown"
}

// checkProcessDanger applies heuristics to flag suspicious processes
func checkProcessDanger(cmdline string, uid int, userShells map[int]string) bool {
	if len(strings.Fields(cmdline)) == 0 {
		return false
	}
	cmdBase := filepath.Base(strings.Fields(cmdline)[0])
	lowerCmd := strings.ToLower(cmdline)

	// CRITICAL!!!: Debug tools are always dangerous (direct exploitation indicators)
	for _, critical := range CriticalProcesses {
		if strings.EqualFold(cmdBase, critical) {
			return true
		}
	}

	//  Network tools with suspicious patterns (nc -l = listening shell)
	if strings.EqualFold(cmdBase, "nc") || strings.EqualFold(cmdBase, "ncat") {
		// Only flag if listening (-l option) or executing shell
		if strings.Contains(lowerCmd, " -l") || strings.Contains(lowerCmd, "-e /bin/") {
			return true
		}
	}

	//  Sensitive keywords in cmdline (potential credential leak)
	sensitiveKeywords := []string{"pass=", "pwd=", "secret=", "token=", "api_key"}
	for _, key := range sensitiveKeywords {
		if strings.Contains(lowerCmd, key) {
			return true
		}
	}

	//  High-risk shell execution by non-login system accounts (e.g., www-data, nobody running bash/sh)
	if uid != 0 {
		if shell, ok := userShells[uid]; ok {
			if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
				if strings.EqualFold(cmdBase, "bash") || strings.EqualFold(cmdBase, "sh") || strings.EqualFold(cmdBase, "dash") || strings.EqualFold(cmdBase, "zsh") {
					// Ignore standard display manager session launchers (e.g. LightDM greeter sessions)
					if strings.Contains(lowerCmd, "lightdm-greeter-session") || strings.Contains(lowerCmd, "gdm-session-worker") || strings.Contains(lowerCmd, "sddm-helper") {
						return false
					}
					return true
				}
			}
		}
	}

	return false
}

// PtraceScopeResult holds the ptrace_scope value and whether it's exploitable
type PtraceScopeResult struct {
	Scope       int
	IsDangerous bool
	Reason      string
}

// ScanPtraceScope checks /proc/sys/kernel/yama/ptrace_scope.
// 0 = unrestricted (classic ptrace): any process can attach to any other.
// This means you can inject shellcode directly into a root process.
func ScanPtraceScope() (*PtraceScopeResult, error) {
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		// File may not exist if Yama is not loaded -> also unrestricted
		return &PtraceScopeResult{
			Scope:       0,
			IsDangerous: true,
			Reason:      "Yama LSM not loaded: ptrace unrestricted (equivalent to scope=0)",
		}, nil
	}
	val, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	isDangerous := val == 0
	reason := ""
	switch val {
	case 0:
		reason = "ptrace_scope=0: unrestricted — any process can ptrace any other process. Allows for cross-process memory injection."
	case 1:
		reason = "ptrace_scope=1: restricted to parent/child (default on most distros)"
	case 2:
		reason = "ptrace_scope=2: only CAP_SYS_PTRACE can use ptrace"
	case 3:
		reason = "ptrace_scope=3: ptrace fully disabled"
	}
	return &PtraceScopeResult{Scope: val, IsDangerous: isDangerous, Reason: reason}, nil
}

// getProcessEnviron reads the environment variables of a process and flags sensitive keys.
func getProcessEnviron(pid string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
	if err != nil {
		return nil, err // Gracefully return error (EACCES etc.)
	}
	return parseEnviron(data), nil
}

// parseEnviron parses environ bytes into sensitive findings.
func parseEnviron(data []byte) []string {
	var envSecrets []string
	vars := strings.Split(string(data), "\x00")
	sensitiveKeys := []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
		"CREDENTIALS", "AUTH_TOKEN", "ACCESS_KEY", "JWT_TOKEN", "DB_PASS",
		"DB_PASSWORD",
	}

	for _, v := range vars {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		val := parts[1]

		upperKey := strings.ToUpper(key)
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if strings.Contains(upperKey, sk) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			// Skip placeholders and extremely short values
			if isFalsePositive(val) {
				continue
			}

			// Mask only in professional/audit mode; CTF mode shows cleartext for immediate use
			displayVal := val
			if AuditCfg.MaskSecrets {
				displayVal = maskSecretValue(val)
			}
			envSecrets = append(envSecrets, key+"="+displayVal)
		}
	}
	return envSecrets
}

// maskSecretValue masks sensitive values to prevent cleartext credential leakage in output.
func maskSecretValue(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	visibleLen := 4
	if len(val) < visibleLen {
		visibleLen = len(val)
	}
	return val[:visibleLen] + "********"
}

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

// ScanProcesses enumerates the /proc filesystem to find high-value targets
func ScanProcesses() ([]ProcessResult, error) {
	var results []ProcessResult

	// Get current user context to filter out own processes
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)

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
		isDangerous := checkProcessDanger(cmdline, uid)

		results = append(results, ProcessResult{
			PID:         pid,
			User:        userName,
			UID:         uid,
			Command:     cmdline,
			IsDangerous: isDangerous,
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
func checkProcessDanger(cmdline string, uid int) bool {
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

	//  High-risk UID services running shells (system daemons shouldn't have interactive shells) 
	if uid != 0 && (uid < 1000 || uid == 65534) { // system UIDs (www-data, nobody, etc.)
		if strings.EqualFold(cmdBase, "bash") || strings.EqualFold(cmdBase, "sh") {
			return true
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
		reason = "ptrace_scope=0: unrestricted — any process can ptrace any other process. Inject shellcode into a root process."
	case 1:
		reason = "ptrace_scope=1: restricted to parent/child (default on most distros)"
	case 2:
		reason = "ptrace_scope=2: only CAP_SYS_PTRACE can use ptrace"
	case 3:
		reason = "ptrace_scope=3: ptrace fully disabled"
	}
	return &PtraceScopeResult{Scope: val, IsDangerous: isDangerous, Reason: reason}, nil
}

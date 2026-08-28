package scanners

import (
	"fmt"
	"os"
	"strings"
)

// SysctlResult represents a kernel hardening setting that deviates from security baselines.
type SysctlResult struct {
	Key          string `json:"key"`
	CurrentValue string `json:"current_value"`
	ExpectedVal  string `json:"expected_val"`
	RiskLevel    string `json:"risk_level"`
	Reason       string `json:"reason"`
	ExploitHint  string `json:"exploit_hint"`
	IsDangerous  bool   `json:"is_dangerous"`
}

type sysctlCheck struct {
	ProcPath    string
	KeyName     string
	Expected    []string
	RiskLevel   string
	Reason      string
	ExploitHint string
}

var sysctlChecks = []sysctlCheck{
	{
		ProcPath:    "/proc/sys/fs/protected_symlinks",
		KeyName:     "fs.protected_symlinks",
		Expected:    []string{"1"},
		RiskLevel:   "HIGH",
		Reason:      "Symlink protection disabled — allows symlink TOCTOU exploitation in /tmp",
		ExploitHint: "sysctl -w fs.protected_symlinks=1",
	},
	{
		ProcPath:    "/proc/sys/fs/protected_hardlinks",
		KeyName:     "fs.protected_hardlinks",
		Expected:    []string{"1"},
		RiskLevel:   "HIGH",
		Reason:      "Hardlink protection disabled — allows hardlink creation to root-owned files in /tmp",
		ExploitHint: "sysctl -w fs.protected_hardlinks=1",
	},
	{
		ProcPath:    "/proc/sys/fs/suid_dumpable",
		KeyName:     "fs.suid_dumpable",
		Expected:    []string{"0"},
		RiskLevel:   "HIGH",
		Reason:      "SUID core dumps enabled — unprivileged user may read memory/credentials from SUID core dump",
		ExploitHint: "sysctl -w fs.suid_dumpable=0",
	},
	{
		ProcPath:    "/proc/sys/kernel/unprivileged_bpf_disabled",
		KeyName:     "kernel.unprivileged_bpf_disabled",
		Expected:    []string{"1", "2"},
		RiskLevel:   "CRITICAL",
		Reason:      "Unprivileged eBPF enabled — allows non-root users to load eBPF programs (major kernel attack surface)",
		ExploitHint: "sysctl -w kernel.unprivileged_bpf_disabled=1",
	},
	{
		ProcPath:    "/proc/sys/kernel/kptr_restrict",
		KeyName:     "kernel.kptr_restrict",
		Expected:    []string{"1", "2"},
		RiskLevel:   "MEDIUM",
		Reason:      "Kernel pointers exposed in /proc — aids kernel exploit ROP/payload alignment",
		ExploitHint: "sysctl -w kernel.kptr_restrict=2",
	},
	{
		ProcPath:    "/proc/sys/kernel/dmesg_restrict",
		KeyName:     "kernel.dmesg_restrict",
		Expected:    []string{"1"},
		RiskLevel:   "MEDIUM",
		Reason:      "Unprivileged dmesg access enabled — kernel log buffer leaks addresses & system state",
		ExploitHint: "sysctl -w kernel.dmesg_restrict=1",
	},
	{
		ProcPath:    "/proc/sys/kernel/yama/ptrace_scope",
		KeyName:     "kernel.yama.ptrace_scope",
		Expected:    []string{"1", "2", "3"},
		RiskLevel:   "CRITICAL",
		Reason:      "Ptrace scope unrestricted (0) — unprivileged processes can inject memory into same-UID processes",
		ExploitHint: "sysctl -w kernel.yama.ptrace_scope=1",
	},
	{
		ProcPath:    "/proc/sys/kernel/perf_event_paranoid",
		KeyName:     "kernel.perf_event_paranoid",
		Expected:    []string{"2", "3"},
		RiskLevel:   "MEDIUM",
		Reason:      "Perf event subsystem unconstrained — exposes hardware performance counters to unprivileged users",
		ExploitHint: "sysctl -w kernel.perf_event_paranoid=2",
	},
}

// ScanSysctlHardening checks critical procfs sysctl settings against security baselines.
func ScanSysctlHardening() ([]SysctlResult, error) {
	var results []SysctlResult

	for _, check := range sysctlChecks {
		data, err := os.ReadFile(check.ProcPath)
		if err != nil {
			// Sysctl key not present on this kernel / procfs configuration
			continue
		}

		val := strings.TrimSpace(string(data))
		isCompliant := false
		for _, exp := range check.Expected {
			if val == exp {
				isCompliant = true
				break
			}
		}

		if !isCompliant {
			expectedStr := strings.Join(check.Expected, " or ")
			results = append(results, SysctlResult{
				Key:          check.KeyName,
				CurrentValue: val,
				ExpectedVal:  expectedStr,
				RiskLevel:    check.RiskLevel,
				Reason:       check.Reason,
				ExploitHint:  fmt.Sprintf("Recommended baseline: %s (current: %s). Fix: %s", expectedStr, val, check.ExploitHint),
				IsDangerous:  true,
			})
		}
	}

	// 2. Runtime physical & kernel memory device node checks
	userCtx := GetUserContext()
	if userCtx != nil {
		rawMemoryNodes := []struct {
			path      string
			desc      string
			riskLevel string
		}{
			{"/dev/mem", "Direct physical RAM memory node", "CRITICAL"},
			{"/dev/kmem", "Kernel virtual memory node", "CRITICAL"},
			{"/proc/kcore", "Kernel core memory dump", "HIGH"},
		}

		for _, node := range rawMemoryNodes {
			info, err := os.Stat(node.path)
			if err != nil {
				continue
			}
			canRead := isStatReadable(info, userCtx)
			canWrite := isStatWritable(info, userCtx)

			if canRead || canWrite {
				accessType := "readable"
				if canWrite {
					accessType = "writable"
				}
				results = append(results, SysctlResult{
					Key:          node.path,
					CurrentValue: accessType,
					ExpectedVal:  "no-access",
					RiskLevel:    node.riskLevel,
					Reason:       fmt.Sprintf("%s '%s' is %s by current user — permits direct raw kernel/physical memory manipulation", node.desc, node.path, accessType),
					ExploitHint:  fmt.Sprintf("Direct %s access allows arbitrary kernel memory inspection/modification", node.path),
					IsDangerous:  true,
				})
			}
		}
	}

	return results, nil
}

func isStatReadable(info os.FileInfo, userCtx *UserContext) bool {
	return (info.Mode().Perm() & 0004) != 0
}

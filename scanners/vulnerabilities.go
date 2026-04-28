package scanners

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// --- Structs ---

type VersionInfo struct {
	Software    string
	Version     string
	FullOutput  string
	IsDangerous bool
}

type KernelVulnerability struct {
	CVE             string
	Name            string
	Description     string
	ExploitName     string
	AffectedKernels []string // Format: "5.8" or "all"
	IsCritical      bool
}

// --- Data (Ideally move to a JSON/Embed later) ---

var kernelVulnerabilities = []KernelVulnerability{
	{CVE: "CVE-2016-5195", Name: "Dirty COW", AffectedKernels: []string{"2.", "3.", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8"}, IsCritical: true},
	{CVE: "CVE-2022-0847", Name: "Dirty Pipe", AffectedKernels: []string{"5.8", "5.9", "5.10", "5.11", "5.12", "5.13", "5.14", "5.15", "5.16"}, IsCritical: true},
	{CVE: "CVE-2024-1086", Name: "Netfilter UAF", AffectedKernels: []string{"5.14", "5.15", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6"}, IsCritical: true},
}

// --- Version Logic ---

func ScanSystemVersions(timeout time.Duration) ([]VersionInfo, error) {
	var results []VersionInfo
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 1. Kernel Version (Stealth: Read from /proc instead of exec uname)
	kernelVer := "Unknown"
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernelVer = strings.TrimSpace(string(data))
		results = append(results, VersionInfo{
			Software:    "Kernel",
			Version:     kernelVer,
			FullOutput:  kernelVer,
			IsDangerous: len(CheckKernelVulnerabilities(kernelVer)) > 0,
		})
	}

	// 2. Sudo Version
	if out, err := exec.CommandContext(ctx, "sudo", "-V").Output(); err == nil {
		v := extractVersion(string(out), `Sudo version (\d+\.\d+\.\d+(?:p\d+)?)`)
		results = append(results, VersionInfo{
			Software:    "Sudo",
			Version:     v,
			IsDangerous: checkVulnerability(v, "1.9.5p2"), // Example threshold
		})
	}

	// 3. Pkexec (Polkit)
	if out, err := exec.CommandContext(ctx, "pkexec", "--version").Output(); err == nil {
		v := extractVersion(string(out), `pkexec version (\d+\.\d+\.\d+)`)
		results = append(results, VersionInfo{
			Software:    "Polkit/pkexec",
			Version:     v,
			IsDangerous: checkVulnerability(v, "0.120"),
		})
	}

	return results, nil
}

// --- Helper Functions ---

// extractVersion uses regex to find version patterns in messy command outputs
func extractVersion(output, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}
	return "Unknown"
}

// compareVersions handles numeric and "p" suffix (e.g., 1.9.5p2)
func compareVersions(v1, v2 string) int {
	clean := func(s string) []int {
		s = regexp.MustCompile(`[^0-9.]`).ReplaceAllString(s, ".")
		parts := strings.Split(strings.Trim(s, "."), ".")
		var res []int
		for _, p := range parts {
			val, _ := strconv.Atoi(p)
			res = append(res, val)
		}
		return res
	}

	p1, p2 := clean(v1), clean(v2)
	for i := 0; i < len(p1) && i < len(p2); i++ {
		if p1[i] < p2[i] { return -1 }
		if p1[i] > p2[i] { return 1 }
	}
	return 0
}

func checkVulnerability(current, maxVuln string) bool {
	if current == "Unknown" { return false }
	return compareVersions(current, maxVuln) <= 0
}

func CheckKernelVulnerabilities(kernelVersion string) []KernelVulnerability {
	var found []KernelVulnerability
	for _, v := range kernelVulnerabilities {
		for _, affected := range v.AffectedKernels {
			if strings.HasPrefix(kernelVersion, affected) {
				found = append(found, v)
				break
			}
		}
	}
	return found
}
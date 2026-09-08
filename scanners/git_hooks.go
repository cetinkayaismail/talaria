package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// GitHookResult represents an audit finding for a privileged Git repository with user-writable hooks.
type GitHookResult struct {
	RepoPath      string `json:"repo_path"`
	HookPath      string `json:"hook_path"`
	HookName      string `json:"hook_name"`
	OwnerUID      int    `json:"owner_uid"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var defaultSharedRepoDirs = []string{
	"/opt",
	"/srv",
	"/var/www",
	"/usr/local/src",
	"/srv/git",
	"/var/lib/gitolite/repositories",
}

// ScanGitHooks audits shared and deployment repositories for user-writable Git hooks owned by privileged users.
func ScanGitHooks() ([]GitHookResult, error) {
	return scanGitHooksInternal(defaultSharedRepoDirs)
}

func scanGitHooksInternal(parentDirs []string) ([]GitHookResult, error) {
	var results []GitHookResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	targetHooks := map[string]bool{
		"post-merge":    true,
		"post-checkout": true,
		"post-receive":  true,
		"pre-commit":    true,
		"pre-receive":   true,
		"update":        true,
	}

	for _, parentDir := range parentDirs {
		entries, err := os.ReadDir(parentDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			candidatePath := filepath.Join(parentDir, entry.Name())

			// 1. Standard repo: check for candidatePath/.git
			var gitDir string
			var isBare bool

			dotGit := filepath.Join(candidatePath, ".git")
			if info, gErr := os.Stat(dotGit); gErr == nil && info.IsDir() {
				gitDir = dotGit
			} else {
				// 2. Bare repo: check if candidatePath contains HEAD and hooks directory directly
				headPath := filepath.Join(candidatePath, "HEAD")
				hooksCheck := filepath.Join(candidatePath, "hooks")
				if _, hErr := os.Stat(headPath); hErr == nil {
					if hInfo, hkErr := os.Stat(hooksCheck); hkErr == nil && hInfo.IsDir() {
						gitDir = candidatePath
						isBare = true
					}
				}
			}

			if gitDir == "" {
				continue
			}

			// Stat the git directory to check ownership
			gInfo, err := os.Stat(gitDir)
			if err != nil {
				continue
			}

			sys := gInfo.Sys()
			if sys == nil {
				continue
			}
			stat, ok := sys.(*syscall.Stat_t)
			if !ok {
				continue
			}

			repoOwnerUID := int(stat.Uid)

			// CRITICAL FILTER: User's own repository is never flagged as privilege escalation
			if repoOwnerUID == userCtx.UID {
				continue
			}

			hooksDir := filepath.Join(gitDir, "hooks")
			hkInfo, err := os.Stat(hooksDir)
			if err != nil {
				continue
			}

			// Check if hooks directory itself is writable by current user
			hkSys := hkInfo.Sys()
			if hkSys != nil {
				if hkStat, ok := hkSys.(*syscall.Stat_t); ok {
					hkUID := int(hkStat.Uid)
					hkGID := int(hkStat.Gid)
					hkMode := uint32(hkInfo.Mode().Perm())

					if userCtx.CanWrite(hkUID, hkGID, hkMode) {
						repoType := "Shared Git repository"
						if isBare {
							repoType = "Shared bare Git repository"
						}
						results = append(results, GitHookResult{
							RepoPath:      candidatePath,
							HookPath:      hooksDir,
							HookName:      "(directory)",
							OwnerUID:      repoOwnerUID,
							RiskLevel:     "HIGH",
							Reason:        fmt.Sprintf("%s at '%s' is owned by UID %d but has a writable hooks directory — attacker can create post-merge or pre-commit hooks that execute as owner during git operations", repoType, candidatePath, repoOwnerUID),
							ExploitHint:   fmt.Sprintf("echo '#!/bin/sh\nchmod +s /bin/bash' > %s/post-merge && chmod +x %s/post-merge", hooksDir, hooksDir),
							Remediation:   fmt.Sprintf("chown -R root:root %s && chmod 0755 %s", hooksDir, hooksDir),
							ComplianceTag: "DevOps-Git-Integrity",
							IsDangerous:   repoOwnerUID == 0,
						})
					}
				}
			}

			// Check individual hook files in hooks directory
			hookEntries, err := os.ReadDir(hooksDir)
			if err != nil {
				continue
			}

			for _, hEntry := range hookEntries {
				hName := hEntry.Name()
				// Skip .sample hook templates
				if strings.HasSuffix(hName, ".sample") {
					continue
				}

				if !targetHooks[hName] {
					continue
				}

				hFilePath := filepath.Join(hooksDir, hName)
				hInfo, err := hEntry.Info()
				if err != nil || !hInfo.Mode().IsRegular() {
					continue
				}

				if sys := hInfo.Sys(); sys != nil {
					if stat, ok := sys.(*syscall.Stat_t); ok {
						hUID := int(stat.Uid)
						hGID := int(stat.Gid)
						hMode := uint32(hInfo.Mode().Perm())

						if userCtx.CanWrite(hUID, hGID, hMode) {
							results = append(results, GitHookResult{
								RepoPath:      candidatePath,
								HookPath:      hFilePath,
								HookName:      hName,
								OwnerUID:      repoOwnerUID,
								RiskLevel:     "CRITICAL",
								Reason:        fmt.Sprintf("Git hook script '%s' in repository owned by UID %d is writable by current user — arbitrary command execution when repository owner performs git commands", hFilePath, repoOwnerUID),
								ExploitHint:   fmt.Sprintf("echo 'chmod +s /bin/bash' >> %s", hFilePath),
								Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", hFilePath, hFilePath),
								ComplianceTag: "DevOps-Git-Integrity",
								IsDangerous:   repoOwnerUID == 0,
							})
						}
					}
				}
			}
		}
	}

	return results, nil
}

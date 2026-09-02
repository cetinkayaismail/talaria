package scanners

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"talaria/internal/walkpool"
)

// SessionHijackResult represents a discovered tmux/screen session hijack vector
type SessionHijackResult struct {
	Path          string `json:"path"`
	TargetUser    string `json:"target_user"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanSessionHijack checks for writable tmux and screen sockets that could allow
// session hijacking to escalate privileges.
func ScanSessionHijack() ([]SessionHijackResult, error) {
	var results []SessionHijackResult

	currentUser, err := user.Current()
	if err != nil {
		return results, err
	}
	uid, _ := strconv.Atoi(currentUser.Uid)

	gidStrings, _ := currentUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	// Check /tmp/tmux-* directories (tmux sockets)
	tmuxDirs, _ := filepath.Glob("/tmp/tmux-*")
	for _, dir := range tmuxDirs {
		for entry := range walkpool.Walk(context.Background(), dir, poolWorkers(), nil) {
			path := entry.Path
			d := entry.Entry

			// Extract target user from dir name: /tmp/tmux-1000/default
			parts := strings.Split(dir, "-")
			if len(parts) < 2 {
				continue
			}
			targetUID := parts[len(parts)-1]

			info, err := d.Info()
			if err != nil {
				continue
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}

			isWritable := false
			if uid == int(stat.Uid) && (stat.Mode&syscall.S_IWUSR != 0) {
				isWritable = true
			} else if userGids[int(stat.Gid)] && (stat.Mode&syscall.S_IWGRP != 0) {
				isWritable = true
			} else if stat.Mode&syscall.S_IWOTH != 0 {
				isWritable = true
			}

			if isWritable {
				// Look up the target user name
				targetUsername := targetUID
				if u, err := user.LookupId(targetUID); err == nil {
					targetUsername = u.Username
				}
				results = append(results, SessionHijackResult{
					Path:          path,
					TargetUser:    targetUsername,
					IsDangerous:   true,
					Reason:        fmt.Sprintf("Tmux socket writable — can hijack session of user %s", targetUsername),
					Remediation:   fmt.Sprintf("chmod 0700 $(dirname %s) && chmod 0600 %s", path, path),
					ComplianceTag: "CIS-Linux-5.4.1 / NIST-AC-3",
				})
			}
		}
	}

	// Check /var/run/screen/ (screen sockets)
	screenDir := "/var/run/screen"
	if info, err := os.Stat(screenDir); err == nil && info.IsDir() {
		entries, err := os.ReadDir(screenDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				userDir := filepath.Join(screenDir, entry.Name())
				sockEntries, err := os.ReadDir(userDir)
				if err != nil {
					continue
				}
				for _, sock := range sockEntries {
					sockPath := filepath.Join(userDir, sock.Name())
					sockInfo, err := os.Stat(sockPath)
					if err != nil {
						continue
					}
					stat, ok := sockInfo.Sys().(*syscall.Stat_t)
					if !ok {
						continue
					}

					isWritable := false
					if uid == int(stat.Uid) && (stat.Mode&syscall.S_IWUSR != 0) {
						isWritable = true
					} else if userGids[int(stat.Gid)] && (stat.Mode&syscall.S_IWGRP != 0) {
						isWritable = true
					} else if stat.Mode&syscall.S_IWOTH != 0 {
						isWritable = true
					}

					if isWritable {
						targetUsername := entry.Name()
						if u, err := user.Lookup(targetUsername); err == nil {
							targetUsername = u.Username
						}
						results = append(results, SessionHijackResult{
							Path:          sockPath,
							TargetUser:    targetUsername,
							IsDangerous:   true,
							Reason:        fmt.Sprintf("Screen socket writable — can hijack session of user %s", targetUsername),
							Remediation:   fmt.Sprintf("chmod 0700 $(dirname %s) && chmod 0600 %s", sockPath, sockPath),
							ComplianceTag: "CIS-Linux-5.4.1 / NIST-AC-3",
						})
					}
				}
			}
		}
	}

	return results, nil
}

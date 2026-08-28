package scanners

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// SSHKeyResult holds findings related to SSH key theft and injection vectors
type SSHKeyResult struct {
	Path          string `json:"path"`
	Type          string `json:"type"` // "private_key", "authorized_keys", ".ssh directory", "host_key"
	TargetUser    string `json:"target_user"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Preview       string `json:"preview,omitempty"` // First line of private key or authorized key comment
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// privateKeyNames are exact filenames that are always SSH private keys
var privateKeyNames = []string{
	"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa",
	"id_rsa.pub",    // Reveal username/host info
	"id_ed25519.pub",
}

// ScanSSHKeys checks:
//  1. Readable private keys in any user's ~/.ssh/ → key theft vector
//  2. Writable authorized_keys or .ssh dir → key injection vector
//  3. Host private keys in /etc/ssh/ that are world-readable → host impersonation
func ScanSSHKeys() ([]SSHKeyResult, error) {
	var results []SSHKeyResult

	currUser, err := user.Current()
	if err != nil {
		return results, err
	}
	currentUID, _ := strconv.Atoi(currUser.Uid)

	gidStrings, _ := currUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	// --- Build candidate .ssh directories ---
	// Include /root/.ssh and all /home/*/.ssh directories
	sshDirs := []string{"/root/.ssh"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				sshDirs = append(sshDirs, filepath.Join("/home", e.Name(), ".ssh"))
			}
		}
	}

	for _, sshDir := range sshDirs {
		dirInfo, err := os.Stat(sshDir)
		if err != nil {
			continue // Dir doesn't exist, skip
		}

		// Determine who owns this .ssh dir
		targetUser := "unknown"
		dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		ownerUID := int(dirStat.Uid)
		if u, err := user.LookupId(strconv.Itoa(ownerUID)); err == nil {
			targetUser = u.Username
		}

		// --- VECTOR 1: Writable .ssh dir (injection) ---
		// Skip our own dir — owning it is expected
		if ownerUID != currentUID && isWritableBy(dirInfo, currentUID, userGids) {
			results = append(results, SSHKeyResult{
				Path:          sshDir,
				Type:          ".ssh directory",
				TargetUser:    targetUser,
				IsDangerous:   true,
				Reason:        "Writable .ssh/ dir → create authorized_keys with your pubkey → ssh " + targetUser + "@localhost",
				Remediation:   fmt.Sprintf("chmod 0700 %s", sshDir),
				ComplianceTag: "CIS-Linux-6.2.7 / DISA-STIG-V-230400",
			})
		}

		// --- Enumerate files inside the .ssh dir ---
		entries, err := os.ReadDir(sshDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fileName := entry.Name()
			filePath := filepath.Join(sshDir, fileName)
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			// --- VECTOR 2: Readable private key (theft) ---
			for _, keyName := range privateKeyNames {
				if strings.EqualFold(fileName, keyName) && ownerUID != currentUID {
					preview := ""
					if rawData, err := os.ReadFile(filePath); err == nil {
						lines := strings.SplitN(string(rawData), "\n", 2)
						if len(lines) > 0 && strings.HasPrefix(lines[0], "-----BEGIN") {
							preview = lines[0]
						}
					}

					isDangerous := false
					reason := ""
					if preview != "" {
						isDangerous = true
						reason = "Readable private key belonging to '" + targetUser + "' → copy to attacker: chmod 400 id_rsa && ssh -i id_rsa " + targetUser + "@<target>"
					} else if ownerUID != currentUID {
						// File exists but couldn't read — report existence anyway
						isDangerous = false
						reason = "Private key found for '" + targetUser + "' but not readable (check permissions)"
					}

					results = append(results, SSHKeyResult{
						Path:          filePath,
						Type:          "private_key",
						TargetUser:    targetUser,
						IsDangerous:   isDangerous,
						Reason:        reason,
						Preview:       preview,
						Remediation:   fmt.Sprintf("chmod 0600 %s", filePath),
						ComplianceTag: "CIS-Linux-5.2.20 / DISA-STIG-V-230400",
					})
					break
				}
			}

			// --- VECTOR 3: Writable authorized_keys (injection) ---
			if fileName == "authorized_keys" && ownerUID != currentUID {
				if isWritableBy(fileInfo, currentUID, userGids) {
					// Count existing authorized keys
					preview := ""
					if rawData, err := os.ReadFile(filePath); err == nil {
						count := 0
						for _, line := range strings.Split(string(rawData), "\n") {
							if strings.HasPrefix(line, "ssh-") || strings.HasPrefix(line, "ecdsa-") {
								count++
							}
						}
						if count > 0 {
							preview = strconv.Itoa(count) + " existing key(s)"
						}
					}
					results = append(results, SSHKeyResult{
						Path:          filePath,
						Type:          "authorized_keys",
						TargetUser:    targetUser,
						IsDangerous:   true,
						Reason:        "Writable authorized_keys for '" + targetUser + "' → append your pubkey → ssh " + targetUser + "@localhost",
						Preview:       preview,
						Remediation:   fmt.Sprintf("chmod 0600 %s", filePath),
						ComplianceTag: "CIS-Linux-6.2.8 / DISA-STIG-V-230400",
					})
				}
			}
		}
	}

	// --- VECTOR 4: SSH host private keys exposed ---
	// /etc/ssh/ssh_host_*_key files should be root-only (600)
	hostKeyDir := "/etc/ssh"
	if entries, err := os.ReadDir(hostKeyDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			// Match host private keys (not .pub files)
			if strings.HasPrefix(name, "ssh_host_") && !strings.HasSuffix(name, ".pub") {
				filePath := filepath.Join(hostKeyDir, name)
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					continue
				}
				fStat, ok := fileInfo.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}
				// World-readable host key = server impersonation risk
				if fStat.Mode&syscall.S_IROTH != 0 {
					results = append(results, SSHKeyResult{
						Path:          filePath,
						Type:          "host_key",
						TargetUser:    "root",
						IsDangerous:   true,
						Reason:        "SSH host private key is world-readable → attacker can impersonate this server (MITM)",
						Remediation:   fmt.Sprintf("chmod 0600 %s && chown root:root %s", filePath, filePath),
						ComplianceTag: "CIS-Linux-5.2.3 / DISA-STIG-V-230400",
					})
				}
			}
		}
	}

	// --- VECTOR 5: SSH Agent Hijacking ---
	// If SSH_AUTH_SOCK is set and readable by us, we can hijack it.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if info, err := os.Stat(sock); err == nil {
			// Check if we can write to the socket (needed for hijacking)
			if isWritableBy(info, currentUID, userGids) {
				results = append(results, SSHKeyResult{
					Path:          sock,
					Type:          "ssh_agent_socket",
					TargetUser:    "active_session",
					IsDangerous:   true,
					Reason:        "Active SSH Agent socket found and writable → hijack via: ssh-add -l",
					Remediation:   fmt.Sprintf("chmod 0700 $(dirname %s)", sock),
					ComplianceTag: "CIS-Linux-5.2.20 / NIST-AC-17",
				})
			}
		}
	}

	return results, nil
}

// isWritableBy returns true if the given file/dir is writable by the user with uid/gids
func isWritableBy(info os.FileInfo, uid int, gids map[int]bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := stat.Mode
	if uid == int(stat.Uid) && (mode&syscall.S_IWUSR != 0) {
		return true
	}
	if gids[int(stat.Gid)] && (mode&syscall.S_IWGRP != 0) {
		return true
	}
	if mode&syscall.S_IWOTH != 0 {
		return true
	}
	return false
}

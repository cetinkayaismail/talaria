package scanners

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// SSHKeyResult holds findings related to SSH key writability and injection vectors
type SSHKeyResult struct {
	Path        string
	Type        string // "authorized_keys", ".ssh directory"
	TargetUser  string
	IsDangerous bool
	Reason      string
}

// ScanSSHKeys checks if authorized_keys files or .ssh directories belonging to
// other users (especially root) are writable by the current user.
// A writable authorized_keys means you can inject your own public key and SSH in as that user.
// NOTE: private key *theft* is already covered by secrets.go — this module only covers
// the *injection* vector (writing into another user's authorized_keys).
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

	// Candidate home directories to check
	sshDirs := []string{"/root/.ssh"}

	// Walk /home to find all user home dirs
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				sshDirs = append(sshDirs, filepath.Join("/home", e.Name(), ".ssh"))
			}
		}
	}

	for _, sshDir := range sshDirs {
		info, err := os.Stat(sshDir)
		if err != nil {
			continue
		}

		// Determine owning user
		targetUser := "unknown"
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		ownerUID := int(stat.Uid)
		if u, err := user.LookupId(strconv.Itoa(ownerUID)); err == nil {
			targetUser = u.Username
		}

		// Skip our own .ssh directory — we own it, it's expected
		if ownerUID == currentUID {
			continue
		}

		// Check if the .ssh directory itself is writable by us
		dirWritable := isWritableBy(info, currentUID, userGids)
		if dirWritable {
			results = append(results, SSHKeyResult{
				Path:        sshDir,
				Type:        ".ssh directory",
				TargetUser:  targetUser,
				IsDangerous: true,
				Reason:      "Writable .ssh directory: drop an authorized_keys file to SSH in as " + targetUser,
			})
		}

		// Check authorized_keys specifically
		authKeysPath := filepath.Join(sshDir, "authorized_keys")
		akInfo, err := os.Stat(authKeysPath)
		if err != nil {
			// File doesn't exist — dir writability covers creating it
			continue
		}

		if isWritableBy(akInfo, currentUID, userGids) {
			results = append(results, SSHKeyResult{
				Path:        authKeysPath,
				Type:        "authorized_keys",
				TargetUser:  targetUser,
				IsDangerous: true,
				Reason:      "Writable authorized_keys: append your public key to get SSH access as " + targetUser,
			})
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

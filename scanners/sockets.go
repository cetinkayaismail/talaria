package scanners

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type SocketResult struct {
	Path        string
	Owner       string
	OwnerUID    int
	Permissions string
	IsWritable  bool
	IsDangerous bool
	Service     string
}

// Optimized list for dangerous socket patterns
var dangerousSockets = []string{
	"docker.sock", "docker", "kubernetes", "k8s", "containerd",
	"cri.sock", "systemd", "dbus", "mysql", "postgres",
	"redis", "mongodb", "lxd", "snapd",
}

func ScanUnixDomainSockets() ([]SocketResult, error) {
	var results []SocketResult

	// 1. Pre-fetch user info once for performance
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)
	groupIDs, _ := currentUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range groupIDs {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	searchPaths := []string{"/var/run", "/run", "/tmp", "/var/tmp", "/var/lib", "/home"}

	for _, basePath := range searchPaths {
		filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // Stealth: ignore permission errors quietly
			}

			// 2. Only check Socket files
			info, err := d.Info()
			if err != nil || (info.Mode()&os.ModeSocket) == 0 {
				return nil
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}

			// 3. Permission Check using Syscall Constants
			mode := stat.Mode
			isWritable := false

			if currentUID == int(stat.Uid) && (mode&syscall.S_IWUSR != 0) {
				isWritable = true
			} else if userGids[int(stat.Gid)] && (mode&syscall.S_IWGRP != 0) {
				isWritable = true
			} else if mode&syscall.S_IWOTH != 0 {
				isWritable = true
			}

			// We only report sockets we can actually interact with
			if !isWritable {
				return nil
			}

			// 4. Identify Service and Danger Level
			fileName := filepath.Base(path)
			service := "Unknown"
			isCriticalSocket := false

			for _, pattern := range dangerousSockets {
				if strings.Contains(strings.ToLower(fileName), pattern) {
					service = pattern
					isCriticalSocket = true
					break
				}
			}

			// A socket is dangerous if it belongs to root and we can write to it
			isDangerous := isCriticalSocket || (stat.Uid == 0)

			results = append(results, SocketResult{
				Path:        path,
				OwnerUID:    int(stat.Uid),
				Permissions: info.Mode().Perm().String(),
				IsWritable:  isWritable,
				IsDangerous: isDangerous,
				Service:     service,
			})

			return nil
		})
	}

	return results, nil
}
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

type SocketResult struct {
	Path          string `json:"path"`
	Owner         string `json:"owner,omitempty"`
	OwnerUID      int    `json:"owner_uid"`
	Permissions   string `json:"permissions"`
	IsWritable    bool   `json:"is_writable"`
	IsDangerous   bool   `json:"is_dangerous"`
	Service       string `json:"service"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// Optimized list for dangerous socket patterns looking for these in ctf's will give us a big lead most of the time direct path to root
// This list is not exhaustive and can be expanded to include more dangerous sockets
// It is also important to note that some of these sockets may not be dangerous and may be used for legitimate purposes
// safeSystemSockets are standard system sockets present on every Linux system.
// These are not exploitable through normal write access and should not be flagged as dangerous.
var safeSystemSockets = map[string]bool{
	"dev-log":                true, // journald log socket
	"socket":                 true, // journald socket
	"stdout":                 true, // journald stdout
	"syslog":                 true, // syslog compat socket
	"notify":                 true, // systemd notification
	"private":                true, // systemd internal control
	"io.systemd.Resolve":     true, // DNS resolver
	"io.systemd.DynamicUser": true, // userdb
	"io.system.ManagedOOM":   true, // OOM manager
	"system_bus_socket":      true, // D-Bus (policy-controlled)
	"request":                true, // uuidd
}

var dangerousSockets = []string{
	"docker.sock", "docker", "kubernetes", "k8s", "containerd",
	"cri.sock", "mysql", "postgres",
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
	seenRealPaths := make(map[string]bool)

	for _, basePath := range searchPaths {
		for entry := range walkpool.Walk(context.Background(), basePath, poolWorkers(), nil) {
			path := entry.Path
			d := entry.Entry

			// 2. Only check Socket files
			info, err := d.Info()
			if err != nil || (info.Mode()&os.ModeSocket) == 0 {
				continue
			}

			// Deduplicate sockets across symlinked directories (e.g. /var/run -> /run)
			realPath, err := filepath.EvalSymlinks(path)
			if err == nil {
				if seenRealPaths[realPath] {
					continue
				}
				seenRealPaths[realPath] = true
			} else {
				if seenRealPaths[path] {
					continue
				}
				seenRealPaths[path] = true
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
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
				continue
			}

			// 4. Identify Service and Danger Level
			fileName := filepath.Base(path)
			service := "Unknown"
			isCriticalSocket := false

			// Skip standard systemd logging/notification sockets entirely to eliminate noise
			if safeSystemSockets[fileName] {
				continue
			}

			for _, pattern := range dangerousSockets {
				if strings.Contains(strings.ToLower(fileName), pattern) {
					service = pattern
					isCriticalSocket = true
					break
				}
			}

			// A socket is dangerous if it matches a known dangerous service pattern
			// and we can write to it
			isDangerous := isCriticalSocket

			results = append(results, SocketResult{
				Path:          path,
				OwnerUID:      int(stat.Uid),
				Permissions:   info.Mode().Perm().String(),
				IsWritable:    isWritable,
				IsDangerous:   isDangerous,
				Service:       service,
				Remediation:   fmt.Sprintf("chmod 0660 %s", path),
				ComplianceTag: "CIS-Linux-5.4.1 / NIST-AC-3",
			})
		}
	}

	return results, nil
}
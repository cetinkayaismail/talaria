package scanners

import (
	"runtime"
	"strings"
)

// poolWorkers returns the number of goroutines to use for the walkpool.
// Capped at 16 to avoid FD exhaustion on systems with tight RLIMIT_NOFILE.
// Minimum of 2 so there is always a worker and the dispatcher has room.
func poolWorkers() int {
	n := runtime.NumCPU() * 2
	if n > 16 {
		n = 16
	}
	if n < 2 {
		n = 2
	}
	return n
}

// GlobalIgnoreDirs is a comprehensive list of directories that should be skipped
// by all scanners to maintain performance and reduce noise.
var GlobalIgnoreDirs = []string{
	"/proc", "/sys", "/dev", "/run", "/snap", "/var/cache",
	"/etc/fonts", "/etc/X11", "/etc/ssl", "/etc/terminfo", "/etc/bash_completion.d",
	"/usr/share/doc", "/usr/share/man", "/usr/share/locale", "/usr/share/icons",
	"/usr/share/fonts", "/usr/share/zoneinfo", "/usr/share/X11",
	"/var/lib/dpkg", "/var/lib/apt", "/var/lib/rpm", "/var/lib/mysql",
	"/var/lib/docker", "/var/lib/systemd", "/lib/modules",
	"/usr/lib/python", "/usr/lib/node_modules", "/usr/include",
	"/sys/fs/cgroup", "/sys/kernel/debug", "/sys/devices", "/var/lib/flatpak",
}

// ShouldIgnore checks if a given path should be ignored based on GlobalIgnoreDirs.
func ShouldIgnore(path string) bool {
	for _, ignore := range GlobalIgnoreDirs {
		if path == ignore || strings.HasPrefix(path, ignore+"/") {
			return true
		}
	}
	return false
}

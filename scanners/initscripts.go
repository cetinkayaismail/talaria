package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ScanInitScripts checks for writable SysV init scripts in /etc/init.d/ and /etc/rc*.d/ (A2).
// These scripts execute as root on service restart or system boot.
func ScanInitScripts() ([]WriteableResult, error) {
	var results []WriteableResult
	ctx := GetUserContext()

	initPaths := []string{"/etc/init.d"}
	for i := 0; i <= 6; i++ {
		initPaths = append(initPaths, fmt.Sprintf("/etc/rc%d.d", i))
	}
	initPaths = append(initPaths, "/etc/rcS.d")

	for _, dir := range initPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())

			// For symlinks in rc*.d, resolve to target (symlinks are always 0777)
			realPath := path
			if entry.Type()&os.ModeSymlink != 0 {
				if resolved, err := filepath.EvalSymlinks(path); err == nil {
					realPath = resolved
				} else {
					continue
				}
			}

			info, err := os.Stat(realPath)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}

			if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
				results = append(results, WriteableResult{
					Path:            path,
					OwnerUID:        int(stat.Uid),
					CurrentUserOwns: ctx.UID == int(stat.Uid),
					IsExecutable:    info.Mode()&0111 != 0,
					IsDangerous:     true,
					Type:            "Writable SysV Init Script",
					RiskLevel:       "CRITICAL",
					Reason:          "SysV init script is writable. Modify to execute code as root on service restart or system boot.",
				})
			}
		}
	}
	return results, nil
}

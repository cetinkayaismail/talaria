package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// XAuthorityResult holds findings about readable .Xauthority files belonging to other users (A4).
type XAuthorityResult struct {
	Path        string `json:"path"`
	TargetUser  string `json:"target_user"`
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason"`
}

// ScanXAuthority checks for readable .Xauthority files of other users for X11 session hijacking.
// Only runs if X11 is active (presence of /tmp/.X11-unix).
func ScanXAuthority() ([]XAuthorityResult, error) {
	var results []XAuthorityResult
	ctx := GetUserContext()

	// Check if X11 is active
	if _, err := os.Stat("/tmp/.X11-unix"); err != nil {
		return results, nil
	}

	// Parse /etc/passwd for user home directories
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return results, nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		username := parts[0]
		homeDir := parts[5]

		// Skip current user and non-real homes
		if username == ctx.Username {
			continue
		}
		if !strings.HasPrefix(homeDir, "/home/") && homeDir != "/root" {
			continue
		}

		xauthPath := filepath.Join(homeDir, ".Xauthority")
		info, err := os.Stat(xauthPath)
		if err != nil {
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		if ctx.CanRead(int(stat.Uid), int(stat.Gid), stat.Mode) {
			results = append(results, XAuthorityResult{
				Path:        xauthPath,
				TargetUser:  username,
				IsDangerous: true,
				Reason:      fmt.Sprintf("X11 authority file readable for user '%s'. Enables session hijacking (keylogging, screenshot capture via xwd/xdpyinfo).", username),
			})
		}
	}

	return results, nil
}

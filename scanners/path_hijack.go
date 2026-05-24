package scanners

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

type PATHHijackResult struct {
	Directory   string
	IsWriteable bool
	IsEmpty     bool
	IsDot       bool
	IsDangerous bool
	Reason      string
}

// ScanPATH checks the directories in the user's $PATH environment variable
// to see if they are writeable, which would allow dropping fake binaries.
// if an elivated process is running and the $PATH is writeable this is a good vector for escalation
func ScanPATH() ([]PATHHijackResult, error) {
	var results []PATHHijackResult

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return results, nil
	}

	currUser, err := user.Current()
	if err != nil {
		return results, err
	}
	uid, _ := strconv.Atoi(currUser.Uid)

	gidStrings, _ := currUser.GroupIds()
	userGids := make(map[int]bool)
	for _, g := range gidStrings {
		id, _ := strconv.Atoi(g)
		userGids[id] = true
	}

	directories := strings.Split(pathEnv, ":")
	seenSecurePath := false

	for _, dir := range directories {
		// Track if we have already passed standard secure system directories
		if dir == "/bin" || dir == "/usr/bin" || dir == "/sbin" || dir == "/usr/sbin" {
			seenSecurePath = true
		}

		isDangerous := false
		reason := ""
		isEmpty := (dir == "")
		isDot := (dir == ".")
		isWriteable := false

		if isEmpty {
			isDangerous = true
			reason = "Empty entry in $PATH (Equivalent to '.')"
			dir = "."
		} else if isDot {
			isDangerous = true
			reason = "'.' is in $PATH (Current directory hijacking)"
		} else {
			info, err := os.Stat(dir)
			if err != nil {
				continue // Directory might not exist
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}

			mode := stat.Mode
			// Check if writeable
			if uid == int(stat.Uid) && (mode&syscall.S_IWUSR != 0) {
				isWriteable = true
			} else if userGids[int(stat.Gid)] && (mode&syscall.S_IWGRP != 0) {
				isWriteable = true
			} else if mode&syscall.S_IWOTH != 0 {
				isWriteable = true
			}

			if isWriteable {
				if !seenSecurePath {
					isDangerous = true
					reason = "Directory in $PATH is writeable and takes precedence over secure system directories (HIGH risk of binary hijacking)"
				} else {
					reason = "Directory in $PATH is writeable, but positioned after secure system paths (low risk of hijacking standard commands)"
				}
			}
		}

		if isDangerous || isWriteable {
			results = append(results, PATHHijackResult{
				Directory:   dir,
				IsWriteable: isWriteable,
				IsEmpty:     isEmpty,
				IsDot:       isDot,
				IsDangerous: isDangerous,
				Reason:      reason,
			})
		}
	}

	return results, nil
}

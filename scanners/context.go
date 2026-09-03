package scanners

import (
	"bufio"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// UserContext holds pre-computed user information to avoid redundant syscalls across scanners (D2).
type UserContext struct {
	UID      int
	GID      int
	Username string
	GIDs     map[int]bool
}

// AuditCfg is the package-level configuration for output formatting.
var AuditCfg struct {
	MaskSecrets bool // Mask credentials in reports
}

var (
	cachedUserCtx *UserContext
	userCtxOnce   sync.Once
)

// InitUserContext pre-computes and caches the current user context. Call once from main.go.
func InitUserContext() {
	userCtxOnce.Do(func() {
		u, err := user.Current()
		if err != nil {
			cachedUserCtx = &UserContext{GIDs: make(map[int]bool)}
			return
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		gids := make(map[int]bool)
		if gs, err := u.GroupIds(); err == nil {
			for _, g := range gs {
				id, _ := strconv.Atoi(g)
				gids[id] = true
			}
		}
		cachedUserCtx = &UserContext{
			UID:      uid,
			GID:      gid,
			Username: u.Username,
			GIDs:     gids,
		}
	})
}

// GetUserContext returns the cached user context.
func GetUserContext() *UserContext {
	if cachedUserCtx == nil {
		InitUserContext()
	}
	return cachedUserCtx
}

// CanWrite checks if the current user can write to a file given its ownership and mode bits.
func (ctx *UserContext) CanWrite(fileUID, fileGID int, mode uint32) bool {
	if ctx.UID == fileUID && (mode&syscall.S_IWUSR != 0) {
		return true
	}
	if ctx.GIDs[fileGID] && (mode&syscall.S_IWGRP != 0) {
		return true
	}
	return mode&syscall.S_IWOTH != 0
}

// CanRead checks if the current user can read a file given its ownership and mode bits.
func (ctx *UserContext) CanRead(fileUID, fileGID int, mode uint32) bool {
	if ctx.UID == fileUID && (mode&syscall.S_IRUSR != 0) {
		return true
	}
	if ctx.GIDs[fileGID] && (mode&syscall.S_IRGRP != 0) {
		return true
	}
	return mode&syscall.S_IROTH != 0
}

// --- GID & UID Name Cache (D4) ---

var (
	gidNameCache sync.Map
	uidNameCache sync.Map
)

// CachedGroupName converts a GID to a group name with caching to avoid repeated lookups.
func CachedGroupName(gid int) string {
	if name, ok := gidNameCache.Load(gid); ok {
		return name.(string)
	}
	name := "unknown"
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		name = g.Name
	}
	gidNameCache.Store(gid, name)
	return name
}

// CachedUserName converts a UID to a username with caching to avoid repeated lookups.
func CachedUserName(uid int) string {
	if name, ok := uidNameCache.Load(uid); ok {
		return name.(string)
	}
	name := strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name = u.Username
	}
	uidNameCache.Store(uid, name)
	return name
}

// SystemUserInfo represents a system user with an active home directory.
type SystemUserInfo struct {
	Username string
	HomeDir  string
}

var (
	systemUsersOnce  sync.Once
	cachedSystemUser []SystemUserInfo
)

// CachedSystemUsers returns the list of system users with valid home directories, parsed once.
func CachedSystemUsers() []SystemUserInfo {
	systemUsersOnce.Do(func() {
		u, err := getSystemUsersFromPasswd()
		if err == nil {
			cachedSystemUser = u
		}
	})
	return cachedSystemUser
}

func getSystemUsersFromPasswd() ([]SystemUserInfo, error) {
	var users []SystemUserInfo

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}

		username := parts[0]
		homeDir := parts[5]

		// Focus strictly on real users (home directory under /home or root's home)
		if strings.HasPrefix(homeDir, "/home/") || homeDir == "/root" {
			if info, err := os.Stat(homeDir); err == nil && info.IsDir() {
				users = append(users, SystemUserInfo{
					Username: username,
					HomeDir:  homeDir,
				})
			}
		}
	}
	return users, nil
}

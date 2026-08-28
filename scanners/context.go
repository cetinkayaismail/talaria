package scanners

import (
	"os/user"
	"strconv"
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

// --- GID Name Cache (D4) ---

var gidNameCache sync.Map

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

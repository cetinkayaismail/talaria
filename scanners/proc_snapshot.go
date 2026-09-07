package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcProcessEntry holds parsed metadata, command line, environment, and socket associations for a process.
type ProcProcessEntry struct {
	PID          int
	UID          int
	Cmdline      string
	Comm         string
	EnvironRaw   []byte   // Raw null-byte separated content of /proc/[pid]/environ (nil if unreadable)
	SocketInodes []string // Inodes associated with socket file descriptors under /proc/[pid]/fd
}

// ProcSnapshot represents a unified, coordinated snapshot of active processes in /proc (OPT-04).
type ProcSnapshot struct {
	CapturedAt time.Time
	Processes  []ProcProcessEntry
	ByPID      map[int]*ProcProcessEntry
	InodeMap   map[string]socketProcessInfo // socket inode -> process name & PID
}

var (
	procSnapMu     sync.Mutex
	cachedSnapshot *ProcSnapshot
	snapshotTTL    = 3 * time.Second
)

// GetProcSnapshot returns a thread-safe, coordinated snapshot of active processes in /proc.
// If a fresh snapshot was taken within snapshotTTL, it is reused to eliminate redundant walks.
func GetProcSnapshot() (*ProcSnapshot, error) {
	procSnapMu.Lock()
	defer procSnapMu.Unlock()

	if cachedSnapshot != nil && time.Since(cachedSnapshot.CapturedAt) < snapshotTTL {
		return cachedSnapshot, nil
	}

	snap, err := captureProcSnapshot()
	if err != nil {
		return nil, err
	}

	cachedSnapshot = snap
	return cachedSnapshot, nil
}

// InvalidateProcSnapshot forces eviction of the cached snapshot.
func InvalidateProcSnapshot() {
	procSnapMu.Lock()
	defer procSnapMu.Unlock()
	cachedSnapshot = nil
}

// captureProcSnapshot executes a single coordinated traversal across /proc.
func captureProcSnapshot() (*ProcSnapshot, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	snap := &ProcSnapshot{
		CapturedAt: time.Now(),
		Processes:  make([]ProcProcessEntry, 0, len(entries)),
		ByPID:      make(map[int]*ProcProcessEntry, len(entries)),
		InodeMap:   make(map[string]socketProcessInfo),
	}

	for _, entryName := range entries {
		pid, err := strconv.Atoi(entryName)
		if err != nil {
			continue
		}

		pidPath := filepath.Join("/proc", entryName)

		// 1. Extract UID from /proc/[pid]/status
		uid := extractProcessUID(pidPath)

		// 2. Extract full command line from /proc/[pid]/cmdline
		cmdline := extractProcessCmdline(pidPath)

		// 3. Extract process comm (fallback for process name)
		comm := extractProcessComm(pidPath)
		if comm == "" {
			if len(strings.Fields(cmdline)) > 0 {
				comm = filepath.Base(strings.Fields(cmdline)[0])
			} else {
				comm = fmt.Sprintf("PID %d", pid)
			}
		}

		// 4. Extract environment variables from /proc/[pid]/environ (decoupled: errors do not abort entry)
		var environRaw []byte
		if envData, err := os.ReadFile(filepath.Join(pidPath, "environ")); err == nil && len(envData) > 0 {
			environRaw = envData
		}

		// 5. Extract socket inodes from /proc/[pid]/fd/* symlinks (decoupled: unreadable fd does not abort entry)
		var socketInodes []string
		fdPath := filepath.Join(pidPath, "fd")
		if fdEntries, err := os.ReadDir(fdPath); err == nil {
			for _, fd := range fdEntries {
				link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
				if err == nil && strings.HasPrefix(link, "socket:[") {
					inode := strings.TrimPrefix(strings.TrimSuffix(link, "]"), "socket:[")
					if inode != "" {
						socketInodes = append(socketInodes, inode)
						snap.InodeMap[inode] = socketProcessInfo{
							Name: comm,
							PID:  pid,
						}
					}
				}
			}
		}

		procEntry := ProcProcessEntry{
			PID:          pid,
			UID:          uid,
			Cmdline:      cmdline,
			Comm:         comm,
			EnvironRaw:   environRaw,
			SocketInodes: socketInodes,
		}

		snap.Processes = append(snap.Processes, procEntry)
	}

	// Index pointers in ByPID map
	for i := range snap.Processes {
		snap.ByPID[snap.Processes[i].PID] = &snap.Processes[i]
	}

	return snap, nil
}

func extractProcessUID(pidPath string) int {
	file, err := os.Open(filepath.Join(pidPath, "status"))
	if err != nil {
		return -1
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.Atoi(fields[1]); err == nil {
					return val
				}
			}
			break
		}
	}
	return -1
}

func extractProcessCmdline(pidPath string) string {
	data, err := os.ReadFile(filepath.Join(pidPath, "cmdline"))
	if err != nil || len(data) == 0 {
		return ""
	}
	// cmdline arguments are null-byte separated
	cmd := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmd)
}

func extractProcessComm(pidPath string) string {
	data, err := os.ReadFile(filepath.Join(pidPath, "comm"))
	if err != nil || len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// GetSocketProcessInfo resolves a socket inode to its owning process name and PID using the snapshot.
func (s *ProcSnapshot) GetSocketProcessInfo(inode string) (socketProcessInfo, bool) {
	if s == nil || s.InodeMap == nil {
		return socketProcessInfo{}, false
	}
	info, exists := s.InodeMap[inode]
	return info, exists
}

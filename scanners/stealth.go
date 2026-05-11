package scanners

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// StealthCfg is a package-level config set once by main before any scan runs.
// All fields default to zero/false so normal ./talaria execution is unaffected.
var StealthCfg struct {
	AtimeRestore bool // --atime-restore: restore file access times after reading
}

// ─── Process Masking ─────────────────────────────────────────────────────────

// MaskProcess changes the visible process name in ps/top/htop.
// It uses two methods for maximum coverage:
//  1. Write to /proc/self/comm  → changes "COMMAND" column in ps
//  2. prctl(PR_SET_NAME)        → changes thread name (visible in htop, /proc/<pid>/status)
//
// Kernel limits comm names to 15 characters; longer names are silently truncated.
// Note: argv[0] (shown by `ps aux`) cannot be reliably overwritten from pure Go
// without CGO. /proc/self/comm covers the most common monitoring tools.
func MaskProcess(name string) {
	// Truncate to kernel limit
	if len(name) > 15 {
		name = name[:15]
	}

	// Method 1: /proc/self/comm — most effective, changes ps COMMAND field
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0644)

	// Method 2: prctl(PR_SET_NAME = 15) — affects thread name
	nameBytes := make([]byte, 16) // 16-byte buffer, last byte must be NUL
	copy(nameBytes, []byte(name))
	_, _, _ = syscall.Syscall6(
		syscall.SYS_PRCTL,
		15, // PR_SET_NAME
		uintptr(unsafe.Pointer(&nameBytes[0])),
		0, 0, 0, 0,
	)
}

// ─── atime (Access Time) Restoration ─────────────────────────────────────────

// ReadFileStealthy reads a file and, if StealthCfg.AtimeRestore is true,
// restores the original atime/mtime afterwards so no access timestamp is
// left in the filesystem metadata. Falls back to plain ReadFile on any error.
//
// Usage inside scanners: replace os.ReadFile(path) with ReadFileStealthy(path)
// in the most sensitive read paths (secrets, ssh_keys).
func ReadFileStealthy(path string) ([]byte, error) {
	if !StealthCfg.AtimeRestore {
		return os.ReadFile(path)
	}

	// Snapshot current timestamps BEFORE we touch the file
	info, err := os.Lstat(path)
	if err != nil {
		return os.ReadFile(path) // fallback
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return os.ReadFile(path) // fallback
	}
	origAtime := syscall.Timespec{Sec: stat.Atim.Sec, Nsec: stat.Atim.Nsec}
	origMtime := syscall.Timespec{Sec: stat.Mtim.Sec, Nsec: stat.Mtim.Nsec}

	// Do the actual read
	data, readErr := os.ReadFile(path)

	// Restore timestamps regardless of read error
	_ = syscall.UtimesNano(path, []syscall.Timespec{origAtime, origMtime})

	return data, readErr
}

// ─── Adaptive Throttling Helpers ─────────────────────────────────────────────

// GetSystemLoad returns the 1-minute load average from /proc/loadavg.
// Returns 0.0 on any error (safe default — no throttling).
func GetSystemLoad() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0.0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0.0
	}
	load, _ := strconv.ParseFloat(fields[0], 64)
	return load
}

// GetNumCPUs counts logical CPU cores from /proc/cpuinfo.
// Returns 1 on any error (safe default — no over-throttling).
func GetNumCPUs() int {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	defer file.Close()

	count := 0
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "processor") {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

// ─── Report Encryption ───────────────────────────────────────────────────────

// EncryptReport encrypts plaintext report data using AES-256-GCM.
// The passphrase is stretched to a 256-bit key via SHA-256.
// Output format: base64(nonce || ciphertext || GCM tag)
//
// To decrypt manually:
//   echo "<base64_blob>" | base64 -d | openssl enc -d -aes-256-gcm ...
//   (or use the paired DecryptReport function)
func EncryptReport(data []byte, passphrase string) ([]byte, error) {
	// Derive a 256-bit key from the passphrase (no salt — offline CTF use)
	keyHash := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Random 12-byte nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext+tag to nonce
	encrypted := gcm.Seal(nonce, nonce, data, nil)

	// Encode as base64 for safe text-file storage
	out := []byte(base64.StdEncoding.EncodeToString(encrypted))
	return out, nil
}

// DecryptReport is the inverse of EncryptReport.
// Provided so the operator can verify encrypted output without external tools.
func DecryptReport(b64data []byte, passphrase string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(b64data))
	if err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

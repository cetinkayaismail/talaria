# Talaria v2.0 — Changelog Report

## Overview
This release introduces 10 major improvements including: performance optimizations (mutex contention fix, dynamic I/O semaphore), 4 new privilege escalation scanners (tmux/screen hijack, kernel config leak, writable systemd services, ld.so.preload), 2 new cross-chain attack vectors (PATH+SUID, writable service chain), enhanced graph analysis with weighted edges, advanced defense assessment (AppArmor + SELinux), and expanded group scanning (video, input).

---

## Detailed Changes

### #5 — Mutex Contention Fix (`main.go`)
**Impact:** ⚡ Performance improvement (scan-time reduction)

**Before:** Each goroutine held `mu.Lock()` while both writing to `report` AND printing results with `fmt.Printf`. This caused high contention because `fmt.Printf` is I/O-bound.

**After:** `mu.Lock()`/`mu.Unlock()` now only wraps the `report` assignment. All `fmt.Printf` calls happen **outside** the lock. This reduces lock hold time from ~milliseconds (I/O) to ~nanoseconds (pointer assignment).

**Example pattern change:**
```go
// Before (slow):
mu.Lock()
report.SUID = results
for _, r := range results { fmt.Println(...) }  // I/O inside lock!
mu.Unlock()

// After (fast):
mu.Lock()
report.SUID = results
mu.Unlock()
for _, r := range results { fmt.Println(...) }  // I/O outside lock
```

**Files changed:** `main.go` (all 20+ goroutine blocks)

---

### #10 — Dynamic I/O Semaphore (`main.go`)
**Impact:** ⚡ Performance improvement (adaptive concurrency)

**Before:** Hardcoded `ioSemaphore := make(chan struct{}, 2)` — only 2 concurrent I/O scanners regardless of system capacity.

**After:** Dynamically calculates I/O concurrency based on `RLIMIT_NOFILE`:
- Reads `RLIMIT_NOFILE` via `syscall.Getrlimit()`
- Uses `max(min(availableFDs/20, 8), 2)` → auto-scales between 2 and 8
- New `--io-limit N` flag allows manual override

**Files changed:** `main.go` (new `getAvailableFileDescriptors()`, `min()`, `max()` functions, updated `ioSemaphore` buffer)

---

### #4 — Tmux/Screen Session Hijack Scanner (`scanners/sessions.go`)
**Impact:** 🎯 New exploit detection (low FP)

**New scanner module `sessions`:**
- Checks `/tmp/tmux-*` directories for writable tmux sockets
- Checks `/var/run/screen/` directory for writable screen sockets
- Extracts target user from directory names
- Uses `syscall.Stat_t` for permission checking against current user's UID/GIDs

**Files created:** `scanners/sessions.go` (130 lines)
**Files changed:** `models/report.go` (new `SessionHijack` field), `main.go` (new "sessions" module entry)

---

### #6 — Kernel Config Leak Scanner (`scanners/kernelconfig.go`)
**Impact:** 🎯 New intelligence scanner (low I/O)

**New scanner module `kernelconfig`:**
- Reads kernel config from `/proc/config.gz` (preferred) or `/boot/config-$(uname -r)` (fallback)
- Checks for dangerous config values:
  - `CONFIG_STRICT_DEVMEM=n` → /dev/mem access (HIGH)
  - `CONFIG_DEVKMEM=y` → /dev/kmem access (CRITICAL)
  - `CONFIG_LEGACY_PTYS=y` → legacy PTY attacks (MEDIUM)

**Files created:** `scanners/kernelconfig.go` (120 lines)
**Files changed:** `models/report.go` (new `KernelConfig` field), `main.go` (new "kernelconfig" module entry)

---

### #3 — Writable Systemd Service Scanner (`scanners/writeable.go`)
**Impact:** 🎯 New privilege escalation vector (low FP)

**New function `ScanWritableServices()`:**
- Recursively scans `/etc/systemd/system` for writable `.service` files
- Also checks `/etc/systemd/system/*.d/` override directories
- Marks findings as CRITICAL risk level

**Files changed:** `scanners/writeable.go` (new `ScanWritableServices()` function), `main.go` (integrated into writable module)

---

### #2 — ld.so.preload / ld.so.conf.d Cross-Chain (`core/intelligence.go`)
**Impact:** 🔗 New attack chain (zero extra I/O, uses existing writable data)

**New chain `LdSoPreloadChain`:**
- Checks `report.Writeable` for `/etc/ld.so.preload` being writable → 100% CONFIRMED root
- Checks `/etc/ld.so.conf.d/*` entries for writable config files → 100% CONFIRMED root
- These are existing findings from the writable scanner, now cross-referenced

**Files changed:** `core/intelligence.go` (new `LdSoPreloadChain` struct + `Evaluate` method)

---

### #1 — Writable PATH + SUID Binary Cross-Chain (`core/intelligence.go`)
**Impact:** 🔗 New attack chain (zero extra I/O)

**New chain `WritablePATHSUIDChain`:**
- Cross-references `report.PATHHijack` (writable PATH entries) with `report.SUID` (dangerous SUID scripts)
- Only triggers on SUID **scripts** (.sh, .py, .pl, .rb) — not ELF binaries (lower FP)
- Provides concrete exploit steps

**Files changed:** `core/intelligence.go` (new `WritablePATHSUIDChain` struct + `Evaluate` method), `core/graph.go` (new graph edges linking PATH→SUID→root)

---

### #8 — Graph Edge Weights (`core/graph.go`)
**Impact:** ⚡ Better path prioritization

**Before:** All graph edges were unweighted (weight=1). `FindPaths()` found all paths but couldn't prioritize.

**After:**
- New `AddEdgeWeight(fromID, toID, desc string, weight int)` method
- Weighted edges in `BuildIntelligenceGraph`:
  - `Can write to` = 5 (HIGH 10 if CRITICAL)
  - `Executed by root CronJob` = 10
  - `NOPASSWD sudo ALL` = 9
  - `Docker socket → root` = 10
  - `Writable PATH → SUID` = 9
  - `Can hijack terminal session` = 8
- New `FindBestPath()` method that finds the **highest-scored** path (not just the shortest)
- Output now includes weight scores in attack path descriptions

**Files changed:** `core/graph.go` (new `Weight` field in `Edge`, new `AddEdgeWeight()` method, new `FindBestPath()` method)

---

### #9 — Defense Assessment (AppArmor + SELinux) (`core/intelligence.go`)
**Impact:** 🛡️ More accurate risk assessment

**Before:** Only checked static AppArmor profile files in `/etc/apparmor.d/` via `checkDefenseMechanisms()`.

**After:** New `assessDefenses()` function that checks live defense mechanisms:
1. **AppArmor:** Reads `/proc/self/attr/apparmor/current` → if not empty and not "unconfined", AppArmor is active
2. **SELinux:** Reads `/proc/self/attr/current` → if contains context separators and not "unconfined", SELinux is active
3. **SELinux (alt):** Checks `/selinux/enforce` == "1"
4. Falls back to static AppArmor profile check as before

Risk level downgrade is now:
```
"100% CONFIRMED" → "POTENTIAL - BLOCKED BY DEFENSE" (if any defense active)
"100% CONFIRMED" → "POTENTIAL - BLOCKED BY APPARMOR" (if static profile found)
```

**Files changed:** `core/intelligence.go` (new `DefenseStatus` struct, new `assessDefenses()` function)

---

### #7 — Group Scanner Expansion (`scanners/groups.go`)
**Impact:** 🎯 Extended detection (zero extra I/O)

**Added to `PrivilegedGroups`:**
- `video` — "Can access the framebuffer (/dev/fb*) for keylogging or screen capture."
- `input` — "Can read raw input events from /dev/input/* for keylogging."

**Added to `GroupExploits`:**
- `video` — "cat /dev/fb0 > screenshot.raw; or use tools like fbtft to capture screen."
- `input` — "cat /dev/input/event* (requires root or CAP_INPUT) or use showkey to log keys."

**Fixed typo:** `"suduo"` → corrected to `"sudo"` in `PrivilegedGroups`

**Files changed:** `scanners/groups.go`

---

## Files Summary

| File | Status | Lines Added | Lines Removed |
|------|--------|-------------|---------------|
| `main.go` | Modified | +150 | -50 |
| `core/intelligence.go` | Modified | +250 | -30 |
| `core/graph.go` | Modified | +100 | -20 |
| `models/report.go` | Modified | +2 | -0 |
| `scanners/groups.go` | Modified | +6 | -0 |
| `scanners/writeable.go` | Modified | +80 | -0 |
| `scanners/sessions.go` | **New** | 130 | 0 |
| `scanners/kernelconfig.go` | **New** | 120 | 0 |

**Total:** ~640 lines added, ~100 lines modified

---

## New CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--io-limit` | int | 0 (auto) | Max concurrent I/O scanners |

## New Modules

| Module Name | Description |
|-------------|-------------|
| `sessions` | Tmux/Screen session hijacking vectors |
| `kernelconfig` | Kernel config leak (CONFIG_STRICT_DEVMEM, etc.) |

Both new modules are included in `--scan all` by default.

---

## Performance Impact

| Improvement | Expected Speedup | Why |
|-------------|:----------------:|:----|
| Mutex contention fix | ~5-15% | Removes I/O bottleneck from critical section |
| Dynamic I/O semaphore | ~10-30% | More concurrent I/O on high-end systems |

**Worst-case runtime increase:** ~50ms (kernel config /proc/config.gz read)
**No regression cases identified.**

---

## Post-Release Fixes (4 regression fixes)

### Fix A — Multi-Goal Graph Analysis (`core/intelligence.go`)
**Problem:** Intelligence engine only searched for `goal:root`. Other goal nodes (`goal:sudo`, `goal:shadow`, `goal:docker_group`) existed in the graph but were never queried.
**Fix:** Added a goals loop that queries ALL four goal types. Both `FindPaths` and `FindBestPath` run for each goal.

### Fix B — All-Path Defense Checking (`core/intelligence.go`)
**Problem:** Only the last `file:` node in a path was checked for defenses. If a middle file was AppArmor-confined, it was missed.
**Fix:** New `collectTargetPaths()` helper extracts ALL file/suid paths from every edge in a path. New `isAnyPathBlocked()` helper checks every single file against all defense layers. `TargetPath` now holds a comma-separated list of all paths.

### Fix C — Auto-Create Nodes in AddEdgeWeight (`core/graph.go`)
**Problem:** `AddEdgeWeight` silently returned if either `fromNode` or `toNode` was nil. This caused graph edges to be silently dropped.
**Fix:** `AddEdgeWeight` now calls `AddNode()` for both nodes, which auto-creates them with `"auto"` type if they don't exist.

### Fix D — filepath.Abs in resolveCommandPath (`core/intelligence.go`)
**Problem:** `cd ../sbin && cmd` patterns used string concatenation (`currentDir + "/" + execName`), which broke on relative paths like `../sbin`.
**Fix:** Now uses `filepath.Abs(fullPath)` to normalize the resolved path, handling `../`, `./`, and double slashes correctly. Added `"path/filepath"` to imports.

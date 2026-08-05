# Talaria — Tier 3 Improvement Plan

Tier 1 (10 items) and Tier 2 (7 items) are fully implemented.
This file now tracks only the remaining **Tier 3** strategic improvements.

---

## Status Overview

| # | Item | Difficulty | Speed | FP Δ | New Vectors | Status |
|---|------|:---:|:---:|:---:|:---:|:---:|
| **B1** | Embedded GTFOBins JSON | 3/5 | 5/5 | ↑ slightly | 🟢 +350 binaries | ✅ DONE |
| **A6+E2** | Systemd EnvironmentFile + Chain | 3/5 | 4/5 | ↓ low FP | 🟢 Critical new vector | ⏳ Pending |
| **D1** | Parallel Walker Pool | 2/5 | 5/5 | — | — | ⏳ Pending |
| **B2** | ELF String Analysis | 2/5 | 3/5 | ↑ moderate | 🟢 Custom SUID vectors | ⏳ Pending (flag-gated) |
| **B6** | Distro Patch Awareness | 2/5 | 5/5 | ↓ highest | — | ⚠️ High-risk data |
| **F1** | Syscall Rate Limiter | 2/5 | 1/5 (intentional) | — | — | ❌ Block on D1 first |
| **E3** | Password Reuse Chain | 3/5 | 4/5 | ↑ heuristic | 🟡 Partial | ⏳ Optional |

---

## Detailed Analysis

---

### ✅ B1 — Embedded GTFOBins JSON
**Status: DONE** (commit `5c27081`)

**What was done:** Replaced the 30-entry hardcoded `trueDangerousBinaries` map with a
`go:embed`-compiled `gtfobins.json` database generated from the official GTFOBins GitHub
repository. 380 binaries with SUID/sudo/shell/file-read/file-write contexts. Zero runtime
overhead — parsed once in `init()`.

**Impact:**
- False Negatives: 30 → 274 SUID-capable binaries (+244 new FN catches)
- Exploit hints: 14 hardcoded → 380 JSON-sourced
- Runtime cost: identical O(1) map lookup

**To refresh the database in future:**
```bash
git clone https://github.com/GTFOBins/GTFOBins.github.io.git /tmp/gtfobins
# Re-run gen_gtfobins.py (recreate it from chat history if needed)
# Then: go build ./...
```

---

### ⏳ A6 — Systemd EnvironmentFile + E2 Chain

**Recommendation: ✅ DO IT NEXT — same pattern as A3/E1, no disruption.**

**What it does:**
Parses all `.service` files for `EnvironmentFile=` directives. If the referenced env file
is writable by the current user, flags it as injectable (`LD_PRELOAD`, `PATH`). The E2
intelligence chain cross-references this to produce a root code-execution path via service
restart.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 3/5 | ~100 lines. Tricky parts: dash-prefix (`EnvironmentFile=-/path` = ignore if missing), systemd specifiers (`%i`, `%n`, `%u`) in paths |
| Speed | 4/5 | Piggybacks on existing systemd service file reads, minimal extra I/O |
| FP Rate | Low | Requires writable env file AND root-owned service simultaneously — rare in well-configured systems |
| New Vectors | Critical | `LD_PRELOAD` injection via env file → root on service restart. Completely absent from Talaria currently |
| Architecture Disruption | Very Low | New file (`scanners/env_file.go`), new report field, new chain — identical pattern to A3/E1 |

**⚠️ FP Risk:**
Some files in `/etc/default/` are writable by design (user-override configs). Mitigation:
flag as `HIGH` not `CRITICAL`, annotate with "verify this is unintentionally writable".

**Implementation notes:**
- Service file locations: `/etc/systemd/system/`, `/lib/systemd/system/`, `/usr/lib/systemd/system/`
- Dash prefix (`EnvironmentFile=-/path`): strip leading `-` from path, and if the file doesn't exist, skip silently (don't report)
- Systemd specifiers (`%i`, `%n`): safest approach is to skip any path containing `%` and note it as "unresolvable specifier" rather than trying to evaluate
- E2 chain depends on A6 data, implement both together

---

### ⏳ D1 — Parallel Walker Pool

**Recommendation: ✅ DO IT — biggest speed win available, but implement one scanner at a time.**

**What it does:**
Converts the 10 `filepath.WalkDir` callsites across 7 scanner files into a shared
goroutine worker-pool so directory traversal runs in parallel instead of serially.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 2/5 (hardest) | ~300 lines new infrastructure. Race condition risk is the main danger |
| Speed | 5/5 | **Largest single speed improvement available.** SSD: 2–4×, NFS: 5–10× |
| FP Rate | No change | Pure traversal — finding logic is untouched |
| New Vectors | None | Same files scanned, just faster |
| Architecture Disruption | Very High | Every scanner using `WalkDir` needs goroutine-safe internal callbacks |

**🔴 Critical implementation rules:**
1. `filepath.SkipDir` semantics **break inside a goroutine pool** — must be handled at the dispatcher level
2. Each scanner callback must be goroutine-safe (no shared slices without mutex)
3. Use a **single shared `errgroup` + semaphore** pattern, not one pool per scanner
4. **Do NOT attempt all 10 callsites in one commit** — start with `secrets.go` (heaviest walker), verify, then expand
5. D1 being done first also makes F1 (Syscall Rate Limiter) trivial — add limiter to the single pool I/O path instead of 17 files

**Affected files:** `scanners/secrets.go`, `scanners/suid.go`, `scanners/writeable.go`,
`scanners/cronjobs.go`, `scanners/fileperms_exploit.go`, `scanners/sockets.go`

---

### ⏳ B2 — ELF String Analysis

**Recommendation: ⚠️ DO IT — but gate behind a `--deep-elf` flag to control FP.**

**What it does:**
For every SUID binary NOT already in the GTFOBins database, reads its `.rodata` ELF
section, extracts strings, and heuristically detects if it calls external commands without
absolute paths — indicating a PATH hijack opportunity.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 2/5 (hardest) | `debug/elf` makes `.rodata` read easy (~30 lines). Hard part: the heuristic for "is this string a command call?" |
| Speed | 3/5 | ~1ms per ELF binary. 200 SUID binaries = ~200ms extra — acceptable but noticeable |
| FP Rate | Moderate increase | A string `"ls"` in `.rodata` ≠ the binary calls `system("ls")`. Heuristic-heavy by nature |
| New Vectors | Unique value | **Only item that catches custom in-house SUID binaries** not on any public list. Critical for HackTheBox/TryHackMe-style CTFs where custom SUID binaries are the challenge |
| Architecture Disruption | Medium | ELF parsing added to SUID scanner hot path, `SUIDResult` gets new field |

**⚠️ FP Risk:**
Strings in `.rodata` have many sources: error messages, format strings, library symbols.
A naive extractor produces many false positives.

**Mitigation — gate behind `--deep-elf` flag:**
```
talaria --deep-elf    # enables ELF string analysis
```
Normal runs stay clean. CTF users get the extra coverage when they explicitly ask for it.

**Heuristic rules (to minimize FP):**
- Only analyze binaries with `OwnerUID == 0` (root-owned SUID)
- Only flag strings that: are ≤15 chars, have no `/` prefix (not absolute path), no shell metacharacters, match known short command names
- Cross-reference against GTFOBins: if the extracted string is in the DB, it's a confirmed hit not a heuristic guess

---

### ⚠️ B6 — Distro Patch Awareness

**Recommendation: ⚠️ DO IT CAREFULLY — wrong data is worse than no data. Ubuntu LTS only.**

**What it does:**
Embeds a per-distro CVE backport version database. When Talaria detects e.g. Ubuntu 22.04
with kernel `5.15.0-91-generic`, it marks known CVEs as "likely_patched" instead of
flagging them as vulnerable.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 2/5 (hardest) | Go implementation: easy. Data sourcing: **ongoing manual work** — backport versions are not centrally published |
| Speed | 5/5 | `go:embed` compile-time, zero runtime cost |
| FP Rate | Highest reduction of all items | Patched CVEs currently show as vulnerable — significant noise in production system scans |
| New Vectors | None | Existing CVE findings annotated differently |
| Architecture Disruption | Medium | New version comparison logic for distro-specific kernel patch formats (not semver) |

**🔴 Critical risk — data quality:**
A wrong "likely_patched" entry **silently hides a real vulnerability**. Example: if Ubuntu
22.04 backported the fix in `5.15.0-91` but your JSON says `5.15.0-89`, you miss a live
CVE on a real target. False negatives here are worse than false positives.

**Safe implementation approach:**
1. Start with **Ubuntu LTS only** (20.04, 22.04, 24.04) — the most common CTF/pentest target
2. Never RHEL/CentOS — their versioning is opaque and error-prone
3. Instead of "likely_patched" label, use "check-if-patched" with a link to Ubuntu's security tracker — gives context without Talaria making the call
4. Source data from `https://ubuntu.com/security/cves` or `usn.ubuntu.com`

---

### ❌ F1 — Syscall Rate Limiter

**Recommendation: ❌ BLOCK ON D1 — after D1 it becomes 20 lines, before it it's 300.**

**What it does:**
Wraps every filesystem syscall in a token-bucket rate limiter so Talaria's I/O pattern
doesn't look like a scanner to IDS/auditd when running in `--stealth` mode.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 2/5 (hardest) | Token-bucket algorithm itself is trivial. Wrapping every `os.Open`, `os.Stat`, `os.ReadFile`, `WalkDir` across 17 files is mechanical but risky |
| Speed | 1/5 | **Intentionally slows everything down** — 5–20× longer scan in stealth mode |
| FP Rate | No change | Logic untouched |
| New Vectors | None | Purely operational |
| Architecture Disruption | Very High | Every filesystem call across the entire codebase must be wrapped |

**🔴 Why to wait for D1:**
Once D1 exists, you have a single centralized I/O path (the worker pool). Slotting a rate
limiter there means touching **1 file** instead of 17. Doing F1 before D1 is wasted effort
that D1 will undo.

**After D1 is done:**
```go
// In the worker pool dispatcher — one place, all scanners covered:
rateLimiter.Wait(ctx)
result, err := doFilesystemOp(...)
```

---

### ⏳ E3 — Password Reuse Chain

**Recommendation: ⏳ OPTIONAL — high FP risk, low-confidence findings only.**

**What it does:**
Cross-references discovered plaintext secrets (from `report.Secrets`) against the
`/etc/passwd` user list to detect potential password reuse across accounts.

**Metrics:**
| Axis | Score | Notes |
|------|-------|-------|
| Difficulty | 3/5 | ~60 lines. String normalization + cross-reference |
| Speed | 4/5 | Pure in-memory string comparison |
| FP Rate | Heuristic-heavy | Same string in different contexts often has different meaning. Only cleartext matches are useful — encoded/hashed secrets are not caught |
| New Vectors | Partial | Catches reused plaintext credentials. Misses hashed/encoded ones |

**⚠️ Implementation constraint:**
Never attempt PAM/su authentication to verify — that creates noisy logs and risks lockout.
Report as `POTENTIAL` only, never `CONFIRMED`. Only flag when the exact string appears in
both a secret file and a field where passwords are expected (e.g. `password=`, `passwd=`,
`PASS=` prefixes).

---

## Recommended Implementation Order

```
1st  →  A6 + E2   ✅ Do now  — same pattern as A3/E1, critical vector, low risk
2nd  →  D1        ✅ Careful  — one scanner at a time, start with secrets.go
3rd  →  B2        ⚠️ Flag-gated  — --deep-elf flag, CTF value
4th  →  B6        ⚠️ Data-quality gated  — Ubuntu LTS only, "check-if-patched" wording
LAST →  F1        ❌ After D1  — becomes trivial once central I/O pool exists
OPT  →  E3        ⏳ Optional  — low confidence, POTENTIAL-only findings
```

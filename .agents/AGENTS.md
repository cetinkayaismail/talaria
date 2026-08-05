# Talaria Project — Agent Rules

---

## Language

Always communicate in **English** — in chat responses, code comments, variable names,
commit messages, and documentation — unless the user explicitly asks otherwise.
Never switch to another language unprompted.

---

## Pre-Change Metric Report

Before implementing **any** code change (feature, scanner, chain, fix, refactor),
you MUST produce a short report covering these 5 metrics:

```
📊 Pre-Change Report: <Item Name>
─────────────────────────────────────────────────────
⚡ Speed impact       : <e.g. "<5ms single ReadDir", "2-4x faster walk", "zero — in-memory only">
📉 FP rate change     : <e.g. "reduces noise — skips user-owned temp files", "slight increase — more binaries flagged", "no change">
🏗️  Architecture risk  : <e.g. "additive only — new file, no existing code touched", "HIGH — 7 scanner files refactored">
🎯 New vectors added  : <e.g. "writable postrotate script (was invisible)", "none — data replacement">
🔍 Vectors that could be missed : <e.g. "inline shell snippets skipped by design", "none identified">
─────────────────────────────────────────────────────
Recommendation: <proceed / proceed with caution / block on X first>
```

This report must appear **before** any file is created or edited.
Do not skip this step even for small changes.

---

## Automatic Changelog Updates

After **every implementation commit**, you MUST update `CHANGELOG.md` without being asked.
Do not wait for the user to say "add to changelog" or "record the changes".

### Rule

Whenever you implement a feature, scanner, chain, or fix and commit it:
1. Immediately add a new entry to `CHANGELOG.md` under `## Detailed Changes`
2. Place it at the **top** of the section (newest first, above existing entries)
3. Assign the next sequential entry number (`#26`, `#27`, etc.)
4. Then commit `CHANGELOG.md` along with or immediately after the implementation commit

### Entry format to follow

```markdown
### #XX — <Short title> (`<files changed>`)
**Impact:** <emoji + one-line impact summary>

- **<Item ID> — <Full name> (`<primary file>`):** <What it does, what was there before, what changed, why it matters>

**Files changed:** `file1`, `file2` *(new if applicable)*

---
```

### Impact emoji guide
- 🎯 = New detection vector
- 📉 = False positive reduction
- ⚡ = Speed improvement
- 🧠 = Smarter output / intelligence engine
- 🛡️ = Defense / stealth improvement
- 🔧 = Refactor / technical debt reduction

### What to include in the entry
- What the item ID is (e.g. A3, B1, D1)
- What was there before (e.g. "previously hardcoded 30-entry map")
- What changed (concrete, specific)
- The measurable impact (e.g. "+350 binaries", "<5ms", "2 new vectors")
- Files changed (with *(new)* marker for new files)

---

## Improvement Analysis File

`improvement_analysis.md` tracks the remaining **Tier 3** strategic improvements.

After implementing a Tier 3 item:
1. Mark it as `✅ DONE` in the Status Overview table
2. Add `**Status: DONE** (commit <hash>)` under its detail section
3. Do NOT delete the analysis — keep it for reference

---

## Build Verification

After every code change, always run:
```bash
/usr/local/go/bin/go build ./... && /usr/local/go/bin/go vet ./...
```
before committing. Never commit code that does not build.

---

## Git Config

If you see "dubious ownership" errors from git, run:
```bash
git config --global --add safe.directory /home/ismail/Desktop/go_projects/talaria
```

Go binary is at: `/usr/local/go/bin/go`

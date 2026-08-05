# Talaria Project — Agent Rules

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

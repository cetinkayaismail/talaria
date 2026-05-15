# Last Changes (Latest Updates)

This document contains the latest features and architectural updates added to Talaria. Very old updates have been cleaned up.

## 1. Intelligence Engine Modularization & Architecture Refactoring
- **Rule-Based Engine:** The hardcoded post-scan correlation logic was completely removed. It was replaced with the `core/intelligence.go` module, creating an infinitely expandable engine operating through the `AttackChain` interface.
- **Enterprise Package Architecture:** To resolve circular import issues and maintain code cleanliness, the core `ScanReport` structure was moved to `models/report.go`. `main.go` was refactored into a lightweight entrypoint that simply parses arguments.
- **Lightweight Attack Graph (DFS):** Integrated a Micro-Graph architecture into the Intelligence Engine. Instead of graphing the entire filesystem (which causes combinatorial explosion and memory issues), it graphs only "interesting" findings (writable files, cronjobs, docker socket) and runs a Depth-First Search (DFS) to map out complex, multi-step attack chains with zero speed degradation.
- **Directory Cleanup:** All research and security notes (e.g., `FUTURE_PLANS.md`, `SECURITY_REPORT.md`) were isolated into the `internal/` folder to prevent them from being pushed to GitHub, and security policies were moved to the standard `.github/` folder.

## 2. Context-Aware Risk Downgrading (AppArmor)
- **Smart Defense Verification:** The scanner no longer blindly reports every finding as `%100 CONFIRMED`. When the engine finds an attack chain, it checks if the target file (e.g., `pkexec` or `docker`) is restricted by an **AppArmor** profile (via static file presence check).
- **False Positive (FP) Reduction:** If the vulnerability is blocked by AppArmor, the engine downgrades the risk from `[CRITICAL]` to `[POTENTIAL - BLOCKED BY APPARMOR]`. This prevents Pentesters from wasting time on unexploitable vectors.

## 3. Terminal Output Synchronization (Output Lock)
- **Clean Reporting:** Prevented the output of concurrently running modules from interleaving or mixing on the screen. The output of each module is synchronized using a Mutex lock, presenting the live report as a professional, sequential block in the terminal.

## 4. New Vulnerability Modules (2026)
- **Systemd-Machined LPE (CVE-2026-4105 & CVE-2026-40224):** Added detection for D-Bus/Varlink vulnerabilities in systemd v259.
- **Systemd Generators:** Writable systemd generator folders were added to the report as a root privilege escalation (LPE) vector.
- **Dirty Frag (CVE-2026-43284 / CVE-2026-43500) & Fragnesia (CVE-2026-46300):** Included detection for page cache manipulation and XFRM subsystem (RFC 8229) vulnerabilities.
- **Copy Fail (CVE-2026-31431) & AF_UNIX Race (CVE-2026-31673):** Added checks for kernel crypto subsystem and socket diagnostics race conditions.

## 5. Professional Mode (--professional / -p)
- **Clean Report Mode:** Integrated a professional mode that hides exploit commands and unnecessary CTF-style explanations. This lists only the technical findings, making the output ready to be directly copy-pasted into penetration testing audit reports.

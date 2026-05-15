# Last Changes - Talaria Intelligence Engine

## [2026-05-15] - Offensive Intelligence & UI Refinement
### Added
- **Process-Aware Network Mapping**: The network scanner now resolves inodes to process names (e.g., `mysqld`, `sshd`) for better context.
- **Micro-Graph DFS Pathfinding**: Integrated a lightweight DFS engine to identify multi-step privilege escalation chains (e.g., Writable File -> Cronjob -> Root).
- **Antik Kernel Coverage**: Added `CVE-2010-3904` (RDS) and `CVE-2010-4347` (Half-Nelson) for legacy 2.6.x kernel exploitation support.

### Changed
- **LPE-Centric Network Logic**: Re-prioritized `127.0.0.1` listeners. Local services (MySQL, Redis, Docker) are now flagged as high-priority LPE vectors.
- **Strict Network Filtering**: Excluded default noisy ports (22, 80, 443) and suppressed non-root exposed services to ensure an actionable report.
- **Secret Scanner De-Noising**: Removed generic `syslog` and `auth.log` filename patterns to eliminate `rsyslog` false positives without losing content-based detection.
- **Professional Output**: Synchronized concurrent scanner outputs using mutex-locked blocks to prevent terminal interleaving.

### Fixed
- **Terminal Output Loops**: Restored missing print logic for Processes, Sockets, and File Permissions modules in `main.go`.
- **DFS Path Resolution**: Fixed a bug where relative binary paths in cronjobs/systemd were not being resolved to absolute paths.
- **AppArmor Awareness**: False positive downgrading logic now correctly parses `/etc/apparmor.d/` to identify sandboxed binaries.

---
*Talaria: High-Performance, Context-Aware Linux Reconnaissance.*

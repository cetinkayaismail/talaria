# Last Changes

This update deepens Talaria's analysis capabilities, reduces false positives, and adds new automations for the post-exploitation phase.

## Secret Scanner Intelligence & FP Reduction
- **Advanced Filtering:** Comment lines in configuration files (`#`, `;`, `//`) are no longer scanned, reducing noise from example settings by 80%.
- **Template Variable Detection:** Dynamic template structures like `${VAR}`, `{{KEY}}`, or `$(...)` are now automatically recognized and not reported as "passwords".
- **Sensitive File Classification:** Files like `/etc/shadow`, `/etc/sudoers`, and `gshadow` have been moved to the **CRITICAL** category. If readable, they are presented as the highest priority findings without waiting for content scanning.

## GTFOBins & Automated Exploit Hints
- **Exploit Hint System:** GTFOBins integration has been added for SUID binaries and Linux Capabilities. Now, when a dangerous binary (e.g., `find`, `vim`, `python`) is detected, ready-to-use commands on how to become root with that binary are provided directly in the report.
- **Wide Coverage:** Custom exploit commands for over 20 common Linux binaries have been added to the database.

## SSH Agent Hijacking Detection
- **Agent Socket Scanning:** The `SSH_AUTH_SOCK` environment variable and related socket permissions in the current session are now scanned. If an accessible SSH agent socket is found, how it can be used to hijack an active SSH session is reported.

## New Kernel Vulnerabilities (2026 Update)
- **Dirty Frag (CVE-2026-43284 / CVE-2026-43500)**: Added a deterministic LPE vulnerability that provides root privileges via page cache manipulation, considered the successor to the "Dirty Pipe" vulnerability.
- **Copy Fail (CVE-2026-31431)**: Added a vulnerability providing root access via a logic error in the kernel crypto subsystem (`algif_aead`).
- **AF_UNIX Diagnostic Race (CVE-2026-31673)**: Added a vulnerability allowing privilege escalation via a synchronization error in socket diagnostics.

## Professional Reporting Mode (--professional / -p)
A professional mode has been added for users to get cleaner outputs while preparing penetration testing or audit reports. When this mode is activated, CTF-oriented "step-by-step exploit" hints are removed from the report, presenting only technical findings and risk analysis. The help menu and usage documents have been updated to include this new flag.

## SUID/SGID Analysis Enhancements (SO Hijacking)
The SUID module now not only looks at file names but also examines the ELF headers of binary files to analyze RPATH and RUNPATH values. If a binary has write permission on the directories from which it calls external libraries, this is reported as a potential "Shared Object Hijacking" vector.

## Cron Jobs & Wildcard Attacks
Command analysis within scheduled tasks (cronjobs) has been strengthened. Dangerous patterns involving wildcards, such as 'tar *', 'chmod *', and 'chown *', which allow command execution (command injection) via filenames, are now automatically detected.

## Sensitive File Scanning (History, Cloud & Logs)
The scope of the Secrets module has been expanded. Now, not only standard configuration files but also terminal history (.bash_history, .zsh_history), cloud service configurations (.aws, .kube), and readable system logs (/var/log/auth.log, /var/log/syslog) are scanned for sensitive information (passwords, tokens, API keys).

## Critical Group Analysis & Exploit Guide
When dangerous group memberships (LXD, Docker, Disk, etc.) are detected, technical explanations on how this can be exploited and (when professional mode is off) ready-to-use exploit commands are included in the report. Critical vectors such as access to the root directory of the host system via the LXD group are detailed.

## Targeted Root Scan
Scans on the root directory (/) were limited to avoid performance degradation. However, to avoid missing critical vulnerabilities like "root ssh keys," a very fast, non-recursive (not descending into subdirectories) scanning mechanism targeting specific secret folders (/.ssh, /.aws, /.backup, etc.) has been added. This way, the most critical "hidden" leaks can be detected without creating system load.

## Local Service Audit
A new module has been added to detect critical services like MySQL and Redis running only on the local network (localhost) and allowing unauthenticated access. Dangerous configurations that allow getting a root shell via "User Defined Functions" (UDF), such as accessing MySQL services running with root privileges with a blank password, are now automatically reported.

## Binary Strings PATH Hijack Analysis
Not only scripts but now also compiled (binary) SUID/SGID files are scanned for PATH hijacking risks. To prevent performance loss, only the first 100 KB of binaries in non-standard directories (e.g., /usr/local/bin) are scanned, and dangerous command calls like 'service', 'tar' inside them are analyzed. This allows classic exploitable binaries like 'suid-env' to be detected in milliseconds.

## Browser Secrets & Modern Package Audit
- **Browser Secrets:** Profile directories, saved passwords (logins.json), cookie databases, and history files of popular browsers like Firefox, Chrome, Brave, and Opera are now automatically detected.
- **Package Audit:** A new module has been added for modern package/privilege manager vulnerabilities such as `doas.conf` (nopass settings), Snapd socket permissions, and Flatpak directory permissions.

# Talaria — Comprehensive Scanner Documentation

This document provides an exhaustive, line-of-sight technical breakdown of all **26 specialized scanner modules** built into Talaria. It details the scanning targets, detection logic, privilege escalation mechanics, and heuristics used by each module.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Detailed Module Documentation](#detailed-module-documentation)
   - [1. Sensitive Data Harvesting (`scanners/secrets.go`)](#1-sensitive-data-harvesting-scannerssecretsgo)
   - [2. SUID Binary Auditor (`scanners/suid.go`)](#2-suid-binary-auditor-scannerssuidgo)
   - [3. SGID Binary Auditor (`scanners/suid.go`)](#3-sgid-binary-auditor-scannerssuidgo)
   - [4. Linux Capabilities Scanner (`scanners/capabilities.go`)](#4-linux-capabilities-scanner-scannerscapabilitiesgo)
   - [5. Sudo Privileges & Configuration Auditor (`scanners/sudo.go`)](#5-sudo-privileges--configuration-auditor-scannerssudogo)
   - [6. Cron Jobs & Systemd Timers Scanner (`scanners/cronjobs.go`)](#6-cron-jobs--systemd-timers-scanner-scannerscronjobsgo)
   - [7. Process & Credential Monitoring (`scanners/processes.go`)](#7-process--credential-monitoring-scannersprocessesgo)
   - [8. Writable Files & Directories Auditor (`scanners/writeable.go`)](#8-writable-files--directories-auditor-scannerswriteablego)
   - [9. Logrotate Configuration Auditor (`scanners/logrotate.go`)](#9-logrotate-configuration-auditor-scannerslogrotatego)
   - [10. Systemd EnvironmentFile Auditor (`scanners/env_file.go`)](#10-systemd-environmentfile-auditor-scannersenv_filego)
   - [11. Unix Domain Socket Auditor (`scanners/sockets.go`)](#11-unix-domain-socket-auditor-scannerssocketsgo)
   - [12. System File Permissions Auditor (`scanners/filepermissions.go`)](#12-system-file-permissions-auditor-scannersfilepermissionsgo)
   - [13. Binary Relative PATH Exploit Scanner (`scanners/fileperms_exploit.go`)](#13-binary-relative-path-exploit-scanner-scannersfileperms_exploitgo)
   - [14. Privileged Group Membership Auditor (`scanners/groups.go`)](#14-privileged-group-membership-auditor-scannersgroupsgo)
   - [15. Environment PATH Hijacking Auditor (`scanners/path_hijack.go`)](#15-environment-path-hijacking-auditor-scannerspath_hijackgo)
   - [16. SSH Authorized Keys & Exposed Private Keys (`scanners/ssh_keys.go`)](#16-ssh-authorized-keys--exposed-private-keys-scannersssh_keysgo)
   - [17. Process Ptrace Scope Auditor (`scanners/processes.go`)](#17-process-ptrace-scope-auditor-scannersprocessesgo)
   - [18. Container Environment & Escape Auditor (`scanners/container.go`)](#18-container-environment--escape-auditor-scannerscontainergo)
   - [19. D-Bus System Policy Auditor (`scanners/polkit.go`)](#19-d-bus-system-policy-auditor-scannerspolkitgo)
   - [20. Local Network Service Auditor (`scanners/services.go`)](#20-local-network-service-auditor-scannersservicesgo)
   - [21. Package Manager & Privilege Tool Auditor (`scanners/packages.go`)](#21-package-manager--privilege-tool-auditor-scannerspackagesgo)
   - [22. Active Session & X11 Hijacking (`scanners/sessions.go`, `scanners/xauthority.go`)](#22-active-session--x11-hijacking-scannerssessionsgo-scannersxauthoritygo)
   - [23. Kernel Configuration Audit (`scanners/kernelconfig.go`)](#23-kernel-configuration-audit-scannerskernelconfiggo)
   - [24. PolicyKit Rules Auditor (`scanners/polkit.go`)](#24-policykit-rules-auditor-scannerspolkitgo)
   - [25. Internal Network Connection Auditor (`scanners/network.go`)](#25-internal-network-connection-auditor-scannersnetworkgo)
   - [26. Kernel & System CVE Vulnerability Engine (`scanners/vulnerabilities.go`)](#26-kernel--system-cve-vulnerability-engine-scannersvulnerabilitiesgo)

---

## Architecture Overview

Talaria operates using a concurrent multi-module model. Core system checks are split across independent scanners executed in parallel inside goroutines. 
- **Parallel Traversal**: Filesystem iteration is handled by `internal/walkpool`, a high-throughput bounded worker pool that balances disk I/O while enforcing directory exclusion filters (`GlobalIgnoreDirs`).
- **Context Caching**: System user and group contexts are computed once via `scanners.InitUserContext()` and shared across modules to eliminate redundant `getpwuid` / `getgrgid` syscalls.
- **Correlation Engine**: Individual findings feed into `core.RunIntelligenceEngine()`, which cross-references vulnerabilities to discover multi-stage privilege escalation paths (e.g. Writable Systemd EnvironmentFile + Root Service Restart -> Root Execution).

---

## Detailed Module Documentation

### 1. Sensitive Data Harvesting (`scanners/secrets.go`)
* **Target Directories**: `/home`, `/var/www`, `/opt`, `/srv`, `/etc`, `/var/backups`, `/tmp`, `/dev/shm`, `/root`.
* **Inspection Logic**:
  - **Filename Matching**: Identifies critical key files (`id_rsa`, `id_ed25519`, `.p12`, `.kdbx`, `.bash_history`, `.aws/credentials`, `.kube/config`, `shadow` copies, `sudoers`).
  - **Content Regex Matching**: Inspects config files (`.env`, `config.php`, `settings.py`, `database.yml`, `docker-compose.yml`, `.ovpn`, `my.cnf`, `wp-config.php`) using pre-compiled regex for API tokens, database connection passwords, cloud credentials, and private keys.
* **FP Reduction**: Ignores binary files using MIME/magic byte header detection (`headerPool` byte buffers) and caps maximum scanned file size.

### 2. SUID Binary Auditor (`scanners/suid.go`)
* **Inspection Logic**: Walks the filesystem filtering entries with `ModeSetuid` mode bits (`04000`).
* **Noise Reduction & AppArmor Awareness**:
  - Automatically filters standard, well-audited system SUID binaries (`passwd`, `su`, `sudo`, `chsh`, `pkexec`, `mount`, etc.) unless GTFOBins flags special vectors or ownership anomalies exist.
  - Dynamically checks `/sys/kernel/security/apparmor/profiles` to suppress false positive findings for sandboxed applications under Snap (`/snap/`) and Flatpak (`/var/lib/flatpak/`).
* **Exploit Engine Integration**: Matches binaries against `gtfobins.json` (380+ embedded GTFOBins entries) to output actionable exploit hints.

### 3. SGID Binary Auditor (`scanners/suid.go`)
* **Inspection Logic**: Scans for files with `ModeSetgid` mode bits (`02000`).
* **Privilege Group Auditing**: Flags SGID binaries owned by dangerous system groups (`shadow`, `disk`, `kmem`, `tty`, `audio`, `video`, `staff`).
* **Escalation Vector**: Group ownership of `shadow` permits reading `/etc/shadow`; ownership of `disk` permits raw block device reads (`/dev/sda`).

### 4. Linux Capabilities Scanner (`scanners/capabilities.go`)
* **Inspection Logic**: Invokes system `getcap -r` to audit file capability extended attributes (`security.capability`).
* **Target Capabilities**: Filters for high-risk capabilities: `cap_setuid`, `cap_setgid`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_dac_override`, `cap_dac_read_search`, `cap_fowner`, `cap_fsetid`, `cap_sys_module`.
* **Exploit Context**: Generates capability-specific exploit command hints (e.g. `cap_dac_read_search` file reading or `cap_setuid` process execution).

### 5. Sudo Privileges & Configuration Auditor (`scanners/sudo.go`)
* **Inspection Logic**: Executes `sudo -l -n` (or uses provided password via `sudo -S -l`).
* **Rule Parsing**:
  - Parses output for `NOPASSWD: ALL`, `NOPASSWD: /path/to/bin`, `SETENV`, and `LD_PRELOAD` in `env_keep`.
  - Flags custom `sudoers` rules permitting execution of dangerous binaries listed in GTFOBins.

### 6. Cron Jobs & Systemd Timers Scanner (`scanners/cronjobs.go`)
* **Inspection Targets**: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.daily/*`, `/etc/cron.hourly/*`, `/var/spool/cron/crontabs/*`, `/etc/systemd/system/*.timer`, `/lib/systemd/system/*.timer`.
* **Detection Logic**:
  - Identifies scheduled tasks executing as `root`.
  - Audits invoked scripts/binaries for write permissions by the current unprivileged user.
  - Flags wildcard injection vulnerabilities in cron commands (`tar *`, `chown *`, `rsync *`).

### 7. Process & Credential Monitoring (`scanners/processes.go`)
* **Inspection Targets**: `/proc/[0-9]+/cmdline` and `/proc/[0-9]+/environ`.
* **Detection Logic**:
  - Scans active process command-line arguments for exposed credentials (`--password=`, `-p`, `api_key=`, `token=`).
  - Identifies processes running with elevated privileges that possess writable environment file configurations.

### 8. Writable Files & Directories Auditor (`scanners/writeable.go`)
* **Inspection Logic**: Uses pre-computed `UserContext` to evaluate whether the current user can write (`UserContext.CanWrite`) to root-owned files across system paths.
* **Specialized Sub-Scanners**:
  - **Systemd Generators**: `/lib/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`.
  - **Writable Systemd Services**: Checks `ExecStart`, `ExecStartPre`, `ExecReload` binary paths for write permissions.
  - **Udev Rules**: `/etc/udev/rules.d/`, `/lib/udev/rules.d/`.
  - **MOTD & Profile.d**: `/etc/update-motd.d/`, `/etc/profile.d/`.
  - **SysV Init Scripts**: `/etc/init.d/`, `/etc/rc*.d/`.
  - **Anacrontab**: `/etc/anacrontab`.
  - **At Job Queue**: `/var/spool/at/`, `/var/spool/cron/atjobs/`.

### 9. Logrotate Configuration Auditor (`scanners/logrotate.go`)
* **Inspection Targets**: `/etc/logrotate.conf` and `/etc/logrotate.d/*`.
* **Detection Logic**: Identifies logrotate directives running as root where either the target log file, configuration file, or script execution directives (`prerotate`, `postrotate`) are writable by unprivileged users.

### 10. Systemd EnvironmentFile Auditor (`scanners/env_file.go`)
* **Inspection Targets**: `/etc/systemd/system/*.service`, `/lib/systemd/system/*.service`.
* **Detection Logic**: Parses service units for `EnvironmentFile=` entries. If the environment file is writable by the current user, flags it as vulnerable to environment variable injection (`LD_PRELOAD`, `PATH`).

### 11. Unix Domain Socket Auditor (`scanners/sockets.go`)
* **Inspection Targets**: `/var/run`, `/run`, `/tmp`, `/dev/shm`.
* **Detection Logic**: Filters UNIX domain sockets (`S_IFSOCK`). Identifies writable control sockets for privileged daemons (e.g. `/var/run/docker.sock`, LXC sockets, Podman sockets).

### 12. System File Permissions Auditor (`scanners/filepermissions.go`)
* **Inspection Targets**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/group`, `/etc/gshadow`, `/etc/fstab`.
* **Detection Logic**: Checks mode bits and ownership for dangerous access states (e.g., world-writable `/etc/passwd`, readable `/etc/shadow`).

### 13. Binary Relative PATH Exploit Scanner (`scanners/fileperms_exploit.go`)
* **Inspection Logic**: Inspects SUID/SGID executable binaries for relative system call invocations (e.g., calling `system("service apache2 restart")` instead of `/bin/service`).
* **Exploit Vector**: Enables PATH hijacking where an unprivileged user prepends a malicious binary to `$PATH`.

### 14. Privileged Group Membership Auditor (`scanners/groups.go`)
* **Inspection Targets**: User supplementary group IDs (`u.GroupIds()`).
* **Detection Logic**: Flags dangerous group memberships (`docker`, `lxd`, `disk`, `shadow`, `sudo`, `wheel`, `kmem`, `input`, `libvirt`). Provides targeted escalation guidance for each group.

### 15. Environment PATH Hijacking Auditor (`scanners/path_hijack.go`)
* **Inspection Logic**: Parses the active `$PATH` environment variable.
* **Detection Logic**: Identifies writable directories in `$PATH`, relative path entries (`.`), or empty path elements that allow binary spoofing.

### 16. SSH Authorized Keys & Exposed Private Keys (`scanners/ssh_keys.go`)
* **Inspection Targets**: `~/.ssh/` directories across `/home/*` and `/root`.
* **Detection Logic**:
  - Finds unencrypted SSH private keys (`id_rsa`, `id_ed25519`, `id_ecdsa`).
  - Identifies writable `authorized_keys` files allowing arbitrary public key insertion.

### 17. Process Ptrace Scope Auditor (`scanners/processes.go`)
* **Inspection Target**: `/proc/sys/kernel/yama/ptrace_scope`.
* **Detection Logic**: A value of `0` indicates unrestricted ptrace scope, permitting unprivileged processes to attach (`gdb` / `ptrace`) to other running processes owned by the same user.

### 18. Container Environment & Escape Auditor (`scanners/container.go`)
* **Inspection Targets**: `/.dockerenv`, `/proc/1/cgroup`, `/proc/cmdline`.
* **Detection Logic**: Detects container execution environments and evaluates escape vectors: `--privileged` mode, exposed Docker socket, mounted host filesystems, or dangerous capabilities (`CAP_SYS_ADMIN`).

### 19. D-Bus System Policy Auditor (`scanners/polkit.go`)
* **Inspection Targets**: `/etc/dbus-1/system.d/*.conf`.
* **Detection Logic**: Parses D-Bus XML policy files to identify method calls or signals allowed to `context="default"` or unprivileged users on privileged system buses.

### 20. Local Network Service Auditor (`scanners/services.go`)
* **Inspection Targets**: Loopback services on `127.0.0.1` / `::1`.
* **Detection Logic**: Connects to internal daemons (MySQL, Redis, MongoDB, PostgreSQL, Memcached) to test for blank passwords or missing authentication.

### 21. Package Manager & Privilege Tool Auditor (`scanners/packages.go`)
* **Inspection Logic**: Audits alternative elevation utilities (`doas`, `pkexec`), Snap/Flatpak package permissions, and custom repository configurations.

### 22. Active Session & X11 Hijacking (`scanners/sessions.go`, `scanners/xauthority.go`)
* **Inspection Targets**: `/tmp/tmux-*`, `/tmp/screens/*`, `~/.Xauthority`.
* **Detection Logic**:
  - Identifies readable/writable `tmux` or `screen` sockets belonging to other users.
  - Detects readable `.Xauthority` files enabling X11 session hijacking and keylogging.

### 23. Kernel Configuration Audit (`scanners/kernelconfig.go`)
* **Inspection Targets**: `/proc/config.gz`, `/boot/config-*`.
* **Detection Logic**: Checks for dangerous kernel compilation options (`CONFIG_DEVKMEM=y`, `CONFIG_STRICT_DEVMEM=n`, `CONFIG_LEGACY_VSYSCALL_EMULATE=y`).

### 24. PolicyKit Rules Auditor (`scanners/polkit.go`)
* **Inspection Targets**: `/etc/polkit-1/rules.d/*.rules`, `/etc/polkit-1/localauthority/*.pkla`.
* **Detection Logic**: Analyzes PolicyKit JavaScript rules and local authority files for rules granting `polkit.Result.YES` without authentication.

### 25. Internal Network Connection Auditor (`scanners/network.go`)
* **Inspection Targets**: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`.
* **Detection Logic**: Identifies active internal listening ports while ignoring short-lived ephemeral outbound connections (`>= 32768`) to suppress noise.

### 26. Kernel & System CVE Vulnerability Engine (`scanners/vulnerabilities.go`)
* **Inspection Targets**: `uname -r`, `/etc/os-release`.
* **Detection Logic**: Compares system kernel version against an integrated 2026 CVE database (DirtyFrag, Fragnesia, Copy Fail, AF_UNIX Diagnostic Race, Dirty Pipe, PwnKit). Uses distribution patch awareness to cross-reference backported security patches and eliminate false positives.

---
*Documentation compiled for Talaria v2.0.*

# Talaria — Enterprise Operations & CLI User Guide

Talaria is a modular, zero-dependency, zero-mutation Linux Privilege Escalation and Security Audit Scanner. It can execute comprehensive system-wide audits or selectively target discrete audit domains.

---

## 1. Core Invocation Patterns

### Comprehensive Full-System Audit
Execute all 40 audit modules across the root filesystem:
```bash
./talaria --scan all
```

### Institutional Audit Mode (Credential Masking)
Enable professional reporting mode (`-p` or `--professional`) to sanitize discovered credentials and tokens in terminal output while preserving compliance mappings:
```bash
./talaria --scan all -p
```

### Targeted Module Execution
Target specific audit domains (e.g. SUID executables, Linux capabilities, and sudo privileges):
```bash
./talaria --scan suid,capabilities,sudo
```

### Scoped Filesystem Traversal
Constrain filesystem audits to a designated path (e.g. `/var/www` or `/opt`):
```bash
./talaria --scan writeable,secrets --path /var/www
```

### Excluding High-Volume Modules
Bypass specific modules to optimize execution speed or focus scope:
```bash
./talaria --scan all --exclude network,vulnerabilities
```

### Structured JSON Telemetry Export
Generate machine-readable JSON reports for SIEM ingestion:
```bash
./talaria --scan all -o audit_report.json --format json
```

### Cryptographic Report Archival (AES-256-GCM)
Encrypt the exported audit report at rest using authenticated AES-256-GCM:
```bash
./talaria --scan all -o /dev/shm/audit.enc --encrypt "YourSecureInstitutionalPassphrase"
```

### Explicit Sudo Credential Auditing
Provide sudo authentication non-interactively to audit `sudo -l` rules:
```bash
./talaria --scan sudo --pass 'UserAuthToken123!'
```

---

## 2. Command Line Flag Reference

### Core Execution Flags

| Flag | Default | Type | Description |
|---|---|---|---|
| `--scan` | `all` | string | Comma-separated list of audit modules to execute, or `all`. |
| `--exclude` | `""` | string | Comma-separated list of audit modules to bypass during execution. |
| `--path` | `/` | string | Root directory path for filesystem traversal modules. |
| `-o` | `""` | string | Output file path to persist the generated report. |
| `--format` | `text` | string | Report format: `text` (human-readable) or `json` (Draft 2020-12 schema). |
| `--pass` | `""` | string | Optional sudo password for non-interactive `sudo -l` authorization inspection. |
| `--io-limit` | `0` | int | Maximum concurrent I/O scanning goroutines (default `0`: auto-calculated from `RLIMIT_NOFILE`). |
| `--encrypt` | `""` | string | AES-256-GCM encryption passphrase applied to output report (requires `-o`). |

### Enterprise Reporting Flags

| Flag | Default | Type | Description |
|---|---|---|---|
| `--professional`, `-p` | `false` | bool | Enterprise audit mode: masks discovered credentials, provides structured findings. |

---

## 3. Complete Audit Module Catalog

Talaria provides 40 deterministic audit modules categorized by subsystem:

| Module Identifier | Subsystem | Description |
|---|---|---|
| `secrets` | Credentials & Storage | Sensitive configuration files, credential dumps, database connection strings, cloud keys |
| `suid` | Privileged Binaries | SUID executables cross-referenced against GTFOBins and custom binaries |
| `sgid` | Privileged Binaries | SGID executables with privileged group ownership (shadow, disk, staff) |
| `sudo` | Access Control | Sudoers rules analysis (`NOPASSWD`, `SETENV`, `!authenticate`, `env_keep`) |
| `capabilities` | Execution Controls | Extended Linux file capabilities (`CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`) |
| `cronjobs` | Automation | System and user crontabs, anacron, systemd timers, and wildcard injection targets |
| `processes` | Process Subsystem | Active process arguments with plaintext credentials and inspection of process boundaries |
| `ptrace` | Process Subsystem | Kernel `ptrace_scope` and cross-process memory inspection vulnerabilities |
| `nfs` | Filesystem & Storage | Network File System exports auditing (`no_root_squash` and insecure mount options) |
| `network` | Network Infrastructure | Active listening TCP/UDP sockets, loopback services, and perimeter exposure |
| `writeable` | Filesystem Integrity | World-writable and group-writable system binaries, scripts, and configuration files |
| `sockets` | IPC & Sockets | Privileged Unix domain sockets (Docker daemon socket, system service sockets) |
| `filepermissions` | Filesystem Integrity | Critical system file permission drift (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) |
| `filepermsexploit` | Execution Hijack | SUID/SGID scripts invoking relative binary paths susceptible to PATH hijacking |
| `groups` | Access Control | Privileged supplemental group memberships (docker, lxd, disk, shadow, adm) |
| `pathhijack` | Execution Hijack | Writable directory entries or relative paths (`.`) within system and user `$PATH` |
| `sshkeys` | Credentials & Storage | User `authorized_keys` writability, private key exposure, and active agent sockets |
| `vulnerabilities` | Vulnerability Intel | Deterministic kernel and installed software version CVE mapping (Dirty COW, PwnKit) |
| `container` | Virtualization | Container breakout primitives (privileged mode, mounted docker sockets, sysfs leaks) |
| `dbus` | IPC & Sockets | System D-Bus configuration policies and unprotected remote procedure calls |
| `services` | Service Management | Local daemon auditing (unauthenticated Redis, blank password MySQL, Memcached) |
| `packages` | Package Management | Package manager execution hooks, drop-in directories, and repository writability |
| `sessions` | Session Subsystem | Active tmux and GNU screen Unix domain socket hijacking vectors |
| `kernelconfig` | Kernel Hardening | Leaked kernel configuration options (`CONFIG_STRICT_DEVMEM`, uncompressed kconfig) |
| `polkit` | Access Control | PolicyKit JavaScript rules logic auditing and pkexec authorization rules |
| `environmentfile` | Service Management | Systemd service `EnvironmentFile=` directive writability and injection vectors |
| `pam` | Access Control | Pluggable Authentication Modules configuration, pam_exec scripts, and custom modules |
| `sysctl` | Kernel Hardening | Kernel sysctl runtime baseline inspection (symlink protection, eBPF unprivileged) |
| `systemdoverrides`| Service Management | Systemd service drop-in directories (`*.service.d/*.conf`) write permissions |
| `subuid` | Virtualization | Unprivileged user namespace cloning and SubUID/SubGID allocation ranges |
| `mounts` | Filesystem Integrity | Shared memory and temporary storage mount flags (`noexec`, `nosuid` on `/dev/shm`) |
| `elfrpath` | Execution Hijack | Dynamic ELF `DT_RPATH` / `DT_RUNPATH` search header analysis on privileged binaries |
| `auditd` | Audit & Logging | System audit daemons (`auditd`, `rsyslog`, `journald`) status and rule coverage |
| `udev` | Hardware & Devices | Udev rule definitions (`/etc/udev/rules.d`) and event execution target writability |
| `crondirs` | Automation | System task drop-in directory permission drift (`/etc/cron.d`, `/var/spool/cron`) |
| `procenv` | Process Subsystem | Process environment secret and token harvesting from `/proc/[pid]/environ` |
| `ldnss` | Execution Hijack | Dynamic linker search paths (`/etc/ld.so.conf.d`) and NSS switch configuration |
| `modprobe` | Kernel Hardening | Kernel module blacklists and modprobe execution install targets (`/etc/modprobe.d`) |
| `cloudmeta` | Cloud & Enclaves | In-cluster Kubernetes ServiceAccount tokens and Cloud IMDSv1/v2 endpoints |
| `venvwrap` | Execution Hijack | Python virtual environment site-packages writability and execution wrapper scripts |
| `xauthority` | Session Subsystem | X11 `.Xauthority` session cookie access and graphical session hijacking |

---

## 4. Decrypting Encrypted Reports

Reports encrypted with `--encrypt` utilize AES-256-GCM. Decrypt them using the Talaria programmatic API or standard OpenSSL tools:

### Using Talaria Core Decryption
```go
decryptedBytes, err := core.DecryptReport(encryptedBase64Bytes, "YourSecureInstitutionalPassphrase")
```

### Verification
All scans produce zero persistent side-effects or temporary files on disk when executed without `-o`.

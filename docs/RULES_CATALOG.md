# Exhaustive Security Rules & Remediation Catalog

**Document ID:** CAT-TALARIA-2026-V2  
**Classification:** Tier-1 Enterprise / Institutional Banking Security Standard  
**Compliance Standard:** CIS Linux Benchmark v2.0.0, NIST SP 800-53 Rev. 5, DISA STIG, MITRE ATT&CK  
**Coverage:** 40 Security Domains, 8 Subsystems, 100% Deterministic Remediation Engine  

---

## Catalog Index by Subsystem

1. [Domain 1: Privileged Binaries & Execution Controls](#domain-1-privileged-binaries--execution-controls)
2. [Domain 2: Access Control & Authorization Subsystems](#domain-2-access-control--authorization-subsystems)
3. [Domain 3: Scheduled Tasks & Automated Execution Triggers](#domain-3-scheduled-tasks--automated-execution-triggers)
4. [Domain 4: Kernel, Memory & Device Security](#domain-4-kernel-memory--device-security)
5. [Domain 5: Filesystem & Mount Point Hardening](#domain-5-filesystem--mount-point-hardening)
6. [Domain 6: Credentials, Tokens & In-Memory Secrets](#domain-6-credentials-tokens--in-memory-secrets)
7. [Domain 7: Package Management, Namespaces & Kernel CVEs](#domain-7-package-management-namespaces--kernel-cves)
8. [Domain 8: Container, Cloud & Perimeter Infrastructure](#domain-8-container-cloud--perimeter-infrastructure)

---

## Domain 1: Privileged Binaries & Execution Controls

### `RULE-SUID-01` — SUID / SGID Binaries & GTFOBins Shell Escapes
- **Modules:** `scanners/suid.go`, `scanners/gtfobins.go`
- **Framework Mapping:** CIS 6.1.13, CIS 6.1.14 | NIST AC-6(1), CM-6 | DISA V-230530 | MITRE T1548.001
- **Severity:** `CRITICAL` (GTFOBins match or non-standard path) / `HIGH`
- **Trigger Condition:** Binary with SUID (`04000`) or SGID (`02000`) bit set allows root shell invocation, arbitrary file write, or memory breakout.
- **Remediation Command:**
  ```bash
  # Remove SUID and SGID bits from target executable
  chmod u-s,g-s /path/to/binary
  # Restrict execution to root user and administrative group only
  chown root:root /path/to/binary && chmod 0750 /path/to/binary
  ```
- **Verification:** `find /path/to/binary -perm /6000`

### `RULE-CAP-01` — Extended Linux File Capabilities
- **Module:** `scanners/capabilities.go`
- **Framework Mapping:** CIS 6.1.15 | NIST AC-6(1), CM-6 | DISA V-230531 | MITRE T1548.001
- **Severity:** `CRITICAL` (`CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`)
- **Trigger Condition:** Executable possesses elevated Linux capabilities in extended filesystem attributes (`security.capability`).
- **Remediation Command:**
  ```bash
  # Strip extended file capabilities
  setcap -r /path/to/binary
  ```
- **Verification:** `getcap /path/to/binary`

### `RULE-RPATH-01` — SUID Dynamic ELF RPATH & Dynamic Linker Paths
- **Modules:** `scanners/ld_nss.go`, `scanners/elf_rpath.go`
- **Framework Mapping:** CIS 5.4.2 | NIST SI-7, CM-6 | DISA V-230500 | MITRE T1574.001, T1574.006
- **Severity:** `CRITICAL`
- **Trigger Condition:** Privileged binary contains relative `DT_RPATH` / `DT_RUNPATH` (e.g. `.` or `$ORIGIN`), or user has write permissions on `/etc/ld.so.conf.d/` or `/etc/ld.so.conf`.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/ld.so.conf /etc/ld.so.conf.d /etc/nsswitch.conf
  chmod 0644 /etc/ld.so.conf /etc/ld.so.conf.d/*.conf /etc/nsswitch.conf
  ldconfig
  ```
- **Verification:** `ls -la /etc/ld.so.conf.d/ && ldconfig -p | grep -i local`

---

## Domain 2: Access Control & Authorization Subsystems

### `RULE-SUDO-01` — Sudoers Privilege Delegation & Wildcard Injection
- **Module:** `scanners/sudo.go`
- **Framework Mapping:** CIS 5.3.4, CIS 5.3.7 | NIST AC-6(5), IA-5(1) | DISA V-230534 | MITRE T1548.003
- **Severity:** `CRITICAL` (`NOPASSWD`, `SETENV`, `env_keep+=LD_PRELOAD`, `ALL`)
- **Trigger Condition:** Sudo configuration allows unauthenticated execution or environment variable preservation leading to arbitrary code execution.
- **Remediation Command:**
  ```bash
  # Enforce password authentication and reset environment variables
  visudo -f /etc/sudoers.d/custom_rules
  # Add: Defaults env_reset, timestamp_timeout=5
  chmod 0440 /etc/sudoers /etc/sudoers.d/*
  ```
- **Verification:** `visudo -c`

### `RULE-POLKIT-01` — PolicyKit JavaScript Rules Logic Authorization
- **Module:** `scanners/polkit.go`
- **Framework Mapping:** CIS 5.3.5 | NIST AC-3, CM-6 | DISA V-230535 | MITRE T1548.001
- **Severity:** `CRITICAL`
- **Trigger Condition:** Custom `.rules` file in `/etc/polkit-1/rules.d/` grants `polkit.Result.YES` to unprivileged users or groups without administrative authentication.
- **Remediation Command:**
  ```bash
  # Lock down PolicyKit rule permissions and remove insecure YES grants
  chown -R root:root /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/
  chmod 0750 /etc/polkit-1/rules.d/
  chmod 0640 /etc/polkit-1/rules.d/*.rules
  ```
- **Verification:** `grep -r "Result.YES" /etc/polkit-1/rules.d/`

### `RULE-PAM-01` — Pluggable Authentication Modules (PAM) Hardening
- **Module:** `scanners/pam.go`
- **Framework Mapping:** CIS 5.3.1, CIS 5.3.3 | NIST AC-3, IA-2 | DISA V-230533 | MITRE T1556.002
- **Severity:** `CRITICAL` (writable configuration or `pam_exec` script) / `HIGH`
- **Trigger Condition:** Writable PAM configuration files in `/etc/pam.d/`, unverified custom PAM shared objects, or world-writable scripts invoked by `pam_exec.so`.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/pam.d/ /etc/security/
  chmod 0644 /etc/pam.d/* /etc/security/*.conf
  find /lib/security /lib64/security -name "*.so" -exec chown root:root {} + -exec chmod 0755 {} +
  ```
- **Verification:** `ls -la /etc/pam.d/`

### `RULE-GRP-01` — Privileged Supplemental Group Membership
- **Module:** `scanners/groups.go`
- **Framework Mapping:** CIS 5.4.1 | NIST AC-6(2) | DISA V-230540 | MITRE T1078.003
- **Severity:** `HIGH` (`docker`, `lxd`, `disk`, `shadow`, `adm`, `sudo`)
- **Trigger Condition:** Unprivileged user account is a member of high-privilege Unix groups providing host takeover primitives.
- **Remediation Command:**
  ```bash
  # Remove user from privileged group
  gpasswd -d <username> <group_name>
  ```
- **Verification:** `id <username>`

---

## Domain 3: Scheduled Tasks & Automated Execution Triggers

### `RULE-CRON-01` — Cron Jobs, Systemd Timers & Writable Triggers
- **Modules:** `scanners/cronjobs.go`, `scanners/cron_dirs.go`
- **Framework Mapping:** CIS 5.1.2 through CIS 5.1.9 | NIST CM-6, SI-7 | DISA V-230520 | MITRE T1053.003
- **Severity:** `CRITICAL` (writable script or drop-in directory) / `HIGH`
- **Trigger Condition:** Crontabs, anacron tables, systemd timers, or drop-in directories (`/etc/cron.d`, `/var/spool/cron`) writable by non-root users.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/crontab /etc/cron.* /var/spool/cron
  chmod 0600 /etc/crontab /var/spool/cron/*
  chmod 0700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
  ```
- **Verification:** `ls -ld /etc/cron* /var/spool/cron`

### `RULE-SYSTEMD-01` — Systemd Unit Overrides & EnvironmentFile Injection
- **Modules:** `scanners/systemd_overrides.go`, `scanners/env_file.go`
- **Framework Mapping:** CIS 4.2.1 | NIST CM-6, SI-7 | DISA V-230525 | MITRE T1543.002
- **Severity:** `CRITICAL`
- **Trigger Condition:** User has write permissions to systemd unit override files (`*.service.d/*.conf`) or files referenced by `EnvironmentFile=` directives in privileged units.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/systemd/system/
  find /etc/systemd/system/ -name "*.conf" -exec chmod 0644 {} +
  find /etc/systemd/system/ -type d -exec chmod 0755 {} +
  systemctl daemon-reload
  ```
- **Verification:** `systemctl daemon-reload && systemctl status <service>`

### `RULE-LOGROT-01` — Logrotate Postrotate Scripts & Configuration
- **Module:** `scanners/logrotate.go`
- **Framework Mapping:** CIS 4.2.1 | NIST CM-6 | DISA V-230522 | MITRE T1053
- **Severity:** `CRITICAL` (writable postrotate script) / `HIGH`
- **Trigger Condition:** Writable logrotate configuration in `/etc/logrotate.d/` or execution of non-root writable script inside `postrotate` block.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/logrotate.conf /etc/logrotate.d/
  chmod 0644 /etc/logrotate.conf /etc/logrotate.d/*
  ```
- **Verification:** `logrotate -d /etc/logrotate.conf`

---

## Domain 4: Kernel, Memory & Device Security

### `RULE-SYSCTL-01` — Kernel Sysctl Security Hardening Directives
- **Module:** `scanners/sysctl.go`
- **Framework Mapping:** CIS 1.5.1, CIS 1.5.2 | NIST SI-16, SC-39 | DISA V-230510 | MITRE T1068
- **Severity:** `HIGH`
- **Trigger Condition:** Critical kernel hardening knobs (`fs.protected_symlinks`, `fs.protected_hardlinks`, `kernel.kptr_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.dmesg_restrict`) not set to `1` or `2`.
- **Remediation Command:**
  ```bash
  cat << 'EOF' > /etc/sysctl.d/99-institutional-hardening.conf
  fs.protected_symlinks = 1
  fs.protected_hardlinks = 1
  fs.protected_fifos = 2
  fs.protected_regular = 2
  kernel.kptr_restrict = 2
  kernel.dmesg_restrict = 1
  kernel.unprivileged_bpf_disabled = 1
  kernel.yama.ptrace_scope = 2
  EOF
  sysctl --system
  ```
- **Verification:** `sysctl fs.protected_symlinks kernel.yama.ptrace_scope`

### `RULE-MODPROBE-01` — Modprobe Directives & Kernel Module Loading
- **Module:** `scanners/modprobe.go`
- **Framework Mapping:** CIS 1.1.1.1 through CIS 1.1.1.8 | NIST CM-7 | DISA V-230515 | MITRE T1547.006
- **Severity:** `CRITICAL` (writable install script) / `HIGH`
- **Trigger Condition:** Writable modprobe configuration files in `/etc/modprobe.d/` or `install <module> <target>` directives pointing to writable executables.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/modprobe.d/ /lib/modprobe.d/
  chmod 0644 /etc/modprobe.d/*.conf /lib/modprobe.d/*.conf
  ```
- **Verification:** `ls -la /etc/modprobe.d/`

### `RULE-UDEV-01` — Udev Device Rules & Event Execution
- **Module:** `scanners/udev.go`
- **Framework Mapping:** CIS 1.1.1 | NIST CM-6, SI-7 | DISA V-230518 | MITRE T1546.002
- **Severity:** `CRITICAL` (writable rule or RUN payload)
- **Trigger Condition:** User write permissions to `/etc/udev/rules.d/` or binaries invoked via `RUN+="/path/payload"`.
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/udev/rules.d/ /lib/udev/rules.d/
  chmod 0644 /etc/udev/rules.d/*.rules
  udevadm control --reload-rules && udevadm trigger
  ```
- **Verification:** `udevadm verify /etc/udev/rules.d/`

---

## Domain 5: Filesystem & Mount Point Hardening

### `RULE-PERMS-01` — Critical System File Permissions
- **Module:** `scanners/filepermissions.go`
- **Framework Mapping:** CIS 5.4.4, CIS 6.1.2 through CIS 6.1.9 | NIST CM-6, AC-3 | DISA V-230545 | MITRE T1078
- **Severity:** `CRITICAL` (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/gshadow` writable)
- **Trigger Condition:** World or group write access on core authentication files.
- **Remediation Command:**
  ```bash
  chown root:root /etc/passwd /etc/shadow /etc/gshadow /etc/group
  chmod 0644 /etc/passwd /etc/group
  chmod 0000 /etc/shadow /etc/gshadow
  ```
- **Verification:** `ls -la /etc/passwd /etc/shadow /etc/gshadow`

### `RULE-MOUNTS-01` — Shared Memory & Temporary Partition Mount Flags
- **Module:** `scanners/mounts.go`
- **Framework Mapping:** CIS 1.1.3 through CIS 1.1.8 | NIST CM-6, SC-39 | DISA V-230550 | MITRE T1068
- **Severity:** `HIGH`
- **Trigger Condition:** Partition `/tmp`, `/var/tmp`, or `/dev/shm` is mounted missing `nodev`, `nosuid`, or `noexec`.
- **Remediation Command:**
  ```bash
  # Update /etc/fstab entry:
  # tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
  mount -o remount,nodev,nosuid,noexec /dev/shm
  mount -o remount,nodev,nosuid,noexec /tmp
  ```
- **Verification:** `findmnt /dev/shm`

### `RULE-PATH-01` — PATH Hijacking & Relative Search Entries
- **Module:** `scanners/path_hijack.go`
- **Framework Mapping:** CIS 5.4.4 | NIST SI-7 | DISA V-230552 | MITRE T1574.007
- **Severity:** `CRITICAL` (writable directory preceding system PATH) / `HIGH`
- **Trigger Condition:** User `$PATH` or system `/etc/environment` contains `.`, empty directory entries, or user-writable directories.
- **Remediation Command:**
  ```bash
  # Sanitize /etc/environment and /etc/profile to:
  # PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  chown root:root /etc/environment /etc/profile /etc/profile.d/*
  chmod 0644 /etc/environment /etc/profile
  ```
- **Verification:** `echo $PATH`

### `RULE-NFS-01` — NFS Exports & Root Squash
- **Module:** `scanners/nfs.go`
- **Framework Mapping:** CIS 2.2.7 | NIST AC-3, CM-7 | DISA V-230555 | MITRE T1021.002
- **Severity:** `CRITICAL` (`no_root_squash` enabled)
- **Trigger Condition:** `/etc/exports` grants client root privileges by specifying `no_root_squash`.
- **Remediation Command:**
  ```bash
  # Replace no_root_squash with root_squash in /etc/exports
  sed -i 's/no_root_squash/root_squash/g' /etc/exports
  exportfs -ra
  ```
- **Verification:** `exportfs -v`

---

## Domain 6: Credentials, Tokens & In-Memory Secrets

### `RULE-SEC-01` — Static Credentials, Cloud Keys & Private Keys
- **Modules:** `scanners/secrets.go`, `scanners/ssh_keys.go`
- **Framework Mapping:** CIS 5.2.20, CIS 5.4.3 | NIST IA-5, SC-28 | DISA V-230560 | MITRE T1552.001, T1552.004
- **Severity:** `CRITICAL`
- **Trigger Condition:** Plaintext database connection strings, AWS/GCP/Azure access tokens, or world-readable SSH private keys discovered on filesystem.
- **Remediation Command:**
  ```bash
  # Restrict permissions on SSH keys
  chmod 0700 ~/.ssh && chmod 0600 ~/.ssh/id_* ~/.ssh/authorized_keys
  # Rotate leaked credentials immediately and migrate to institutional vault (HashiCorp Vault / AWS Secrets Manager)
  ```
- **Verification:** `ls -la ~/.ssh/`

### `RULE-PROCENV-01` — Process Environment Token & Secret Harvesting
- **Module:** `scanners/proc_env.go`
- **Framework Mapping:** CIS 1.5.3 | NIST IA-5, SC-28 | DISA V-230562 | MITRE T1055, T1552
- **Severity:** `CRITICAL` (cross-user plaintext tokens in `/proc/[pid]/environ`)
- **Trigger Condition:** Running processes pass database passwords, API tokens, or secrets as environment variables accessible via unhardened procfs.
- **Remediation Command:**
  ```bash
  # Mount procfs with hidepid=2 to restrict process visibility to owning user
  mount -o remount,rw,hidepid=2 /proc
  # Add to /etc/fstab: proc /proc proc defaults,hidepid=2 0 0
  ```
- **Verification:** `mount | grep hidepid`

---

## Domain 7: Package Management, Namespaces & Kernel CVEs

### `RULE-PKG-01` — Package Manager Hooks & Drop-In Repositories
- **Module:** `scanners/packages.go`
- **Framework Mapping:** CIS 1.2.1 | NIST SI-2, CM-7 | DISA V-230570 | MITRE T1574
- **Severity:** `CRITICAL`
- **Trigger Condition:** User write permissions on package hook directories (`/etc/apt/apt.conf.d/`, `/etc/yum/pluginconf.d/`, `/etc/pacman.d/hooks/`).
- **Remediation Command:**
  ```bash
  chown -R root:root /etc/apt/apt.conf.d/ /etc/yum.repos.d/ /etc/pacman.d/
  chmod 0755 /etc/apt/apt.conf.d/
  chmod 0644 /etc/apt/apt.conf.d/*
  ```
- **Verification:** `ls -la /etc/apt/apt.conf.d/`

### `RULE-NS-01` — Unprivileged User Namespaces & SubUID Range Allocations
- **Module:** `scanners/subuid.go`
- **Framework Mapping:** CIS 1.5.4 | NIST SC-39 | DISA V-230572 | MITRE T1068
- **Severity:** `HIGH`
- **Trigger Condition:** `kernel.unprivileged_userns_clone = 1` enabled, allowing unprivileged processes to map root UIDs.
- **Remediation Command:**
  ```bash
  echo "kernel.unprivileged_userns_clone = 0" > /etc/sysctl.d/50-disable-userns.conf
  sysctl -p /etc/sysctl.d/50-disable-userns.conf
  ```
- **Verification:** `sysctl kernel.unprivileged_userns_clone`

---

## Domain 8: Container, Cloud & Perimeter Infrastructure

### `RULE-CLOUD-01` — In-Cluster Kubernetes ServiceAccounts & Cloud IMDS
- **Module:** `scanners/cloud_meta.go`
- **Framework Mapping:** CIS K8s 5.1.6 | NIST AC-6, SC-7 | MITRE T1552.005, T1526
- **Severity:** `CRITICAL`
- **Trigger Condition:** In-cluster Kubernetes token (`/var/run/secrets/kubernetes.io/serviceaccount/token`) present, or unauthenticated Cloud IMDSv1 reachable at `169.254.169.254`.
- **Remediation Command:**
  ```bash
  # Enforce IMDSv2 token requirement on cloud instance:
  # aws ec2 modify-instance-metadata-options --http-tokens required --http-endpoint enabled
  # In Kubernetes, disable automountServiceAccountToken: false on Pod spec
  ```
- **Verification:** `curl -s -m 2 http://169.254.169.254/latest/meta-data/`

### `RULE-CONT-01` — Container Escape Primitives & Mounted Docker Sockets
- **Module:** `scanners/container.go`
- **Framework Mapping:** CIS Docker 5.4, 5.5 | NIST SC-7, AC-3 | MITRE T1611
- **Severity:** `CRITICAL`
- **Trigger Condition:** Container running in `--privileged` mode, `/var/run/docker.sock` mounted into unprivileged container, or sensitive host device nodes exposed.
- **Remediation Command:**
  ```bash
  # Drop privileged flag, revoke access to docker.sock, and enforce non-root user
  chmod 0660 /var/run/docker.sock
  chown root:docker /var/run/docker.sock
  ```
- **Verification:** `docker info --format '{{.SecurityOptions}}'`

# Talaria - User Guide & Usage Documentation

Talaria is highly modular. You can run all scans at once or select specific modules if you know exactly what you are looking for.

## Basic Usage

The most common way to run Talaria is to let it scan everything starting from the root directory:

```bash
./talaria --scan all
```

By default, Talaria prints the output directly to your terminal using colored text to highlight `CRITICAL` findings in red, and `MEDIUM/INFO` findings in yellow.

---

## Command Line Flags

### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scan` | `all` | Comma-separated list of modules to run (e.g., `suid,secrets,capabilities`). |
| `--exclude` | `""` | Comma-separated list of modules to skip (e.g., `network,vulnerabilities`). |
| `--path` | `/` | The directory to start filesystem scans from. |
| `-o` | `""` | File path to save the report to. |
| `--format` | `text` | Output format of the report file (`text` or `json`). |
| `--pass` | `""` | Sudo password for `sudo -l` checks. |

### Stealth Flags

All stealth flags are **opt-in and inactive by default**. Running `./talaria` without any stealth flags behaves identically to previous versions.

| Flag | Default | Description |
|------|---------|-------------|
| `--stealth` | `false` | Enables random delays between module launches to reduce I/O burst signatures. |
| `--delay` | `0` | Base delay between module launches (e.g., `150ms`). |
| `--jitter` | `0` | Maximum random jitter added on top of the base delay. |
| `--mask <name>` | `""` | Replaces the process name visible in `ps`, `top`, and `htop` (e.g., `--mask "[kworker/u2:1]"`). |
| `--atime-restore` | `false` | Restores file access timestamps after reading sensitive files. Defeats atime-based forensic detection. |
| `--throttle <ratio>` | `0` | Pauses automatically when system load/CPU exceeds this ratio (e.g., `0.8`). Reduces anomaly detection exposure during high-activity periods. |
| `--encrypt <key>` | `""` | Encrypts the output report with AES-256-GCM. Requires `-o` to be set. Output is base64-encoded. |
| `--self-destruct` | `false` | Deletes the binary from disk after the scan completes. The report is written before deletion. |

---

## Examples

### 1. Specific Modules Only
```bash
./talaria --scan suid,capabilities
```

### 2. Targeting a Specific Directory
```bash
./talaria --scan writeable,secrets --path /var/www/html
```

### 3. Excluding Noisy Modules
```bash
./talaria --scan all --exclude network,vulnerabilities
```

### 4. Saving Output to JSON
```bash
./talaria --scan all -o report.json --format json
```

### 5. Stealth Mode with Delays
```bash
./talaria --scan all --stealth --delay 200ms --jitter 100ms
```

### 6. Full Stealth Profile
Mask the process name, restore file access times, throttle on system load, and encrypt the report:
```bash
./talaria --scan all \
  --stealth \
  --mask "[kworker/u2:1]" \
  --atime-restore \
  --throttle 0.8 \
  -o /dev/shm/.report \
  --encrypt <passphrase>
```

### 7. Encrypted Report + Self-Destruct
Run a scan, save an encrypted report, then remove the binary:
```bash
./talaria --scan all -o report.enc --encrypt <passphrase> --self-destruct
```
To decrypt later:
```bash
# Decrypt using Go (DecryptReport) or manually:
cat report.enc | base64 -d | openssl enc -d -aes-256-gcm -nosalt -k <passphrase>
```

### 8. RAM-Only Execution (Stealth Bundle)
The stealth bundle extracts the binary into `/dev/shm` (RAM, no disk write), runs it with `--self-destruct` and `--mask` pre-set, then cleans up automatically:
```bash
# Build the bundle on your machine:
make stealth-bundle

# Transfer talaria.sh to the target, then:
./talaria.sh --scan all -o /dev/shm/.r --encrypt <passphrase>

# The binary is never written to a persistent disk path.
# /proc/<pid>/exe shows the path as deleted once the scan completes.
```

### 9. Passing a Known Password
```bash
./talaria --scan sudo --pass 'SecretPassword123'
```

---

## Available Modules

| Module | Description |
|--------|-------------|
| `secrets` | Sensitive files and credentials |
| `suid` | SUID binaries (GTFOBins-matched) |
| `sgid` | SGID binaries (privileged group ownership) |
| `sudo` | sudo -l analysis (NOPASSWD, LD_PRELOAD) |
| `capabilities` | Linux capabilities (cap_setuid, cap_sys_admin) |
| `cronjobs` | Cron jobs, systemd timers, wildcard injection |
| `processes` | Running processes (credentials in args, ptrace) |
| `ptrace` | ptrace_scope check |
| `nfs` | NFS exports (no_root_squash detection) |
| `network` | Open ports and internal services |
| `writeable` | Writable files and directories |
| `sockets` | Unix sockets (Docker sock, privileged sockets) |
| `filepermissions` | Critical system file misconfigurations |
| `filepermsexploit` | SUID/SGID scripts with relative binary calls |
| `groups` | Privileged group membership (docker, lxd, disk) |
| `pathhijack` | Writable or dot entries in $PATH |
| `sshkeys` | SSH key theft and injection vectors |
| `vulnerabilities` | Kernel and software CVE checks |
| `container` | Container escape vectors |
| `dbus` | D-Bus policy misconfigurations |

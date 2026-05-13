<p align="center">
  <img src="logo.png" alt="Talaria Logo" width="300">
</p>

# Talaria - Linux Privilege Escalation Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.20%2B-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://en.wikipedia.org/wiki/Linux)

Developing and maintaining an LPE framework requires constant research and testing against the latest kernel patches and security configurations (if ı miss a new vector pls open a pr). If Talaria helped you pwn a box, escalate your privileges in a annoying lab, or if you simply appreciate the craft.

**Star this repository** – It’s the best way to show support and keep the project alive (makes me happy and motivated :) )

Talaria is a high-performance reconnaissance framework designed for Linux Privilege Escalation. Built with Go, it provides cybersecurity professionals and auditors with a fast, low-noise, and reliable alternative to traditional LPE scripts. 

By leveraging native system calls and concurrent execution, Talaria completes comprehensive system audits in seconds, prioritizing high-signal attack vectors while maintaining a minimal footprint.

## Core Advantages

- **Advanced Binary Analysis:** Performs deep analysis of ELF headers (RPATH/RUNPATH) and binary strings to detect SO Hijacking and PATH injection vectors in compiled SUID/SGID files.
- **Professional Reporting Mode:** Includes a dedicated mode (`--professional`) that suppresses exploit hints and CTF-style tips, providing a clean, action-oriented report suitable for corporate security audits.
- **Intelligence Engine:** Correlates findings to identify complex attack chains, such as writable scripts executed via privileged CronJobs or system services.
- **Operational Security (OPSEC):** Features opt-in stealth mechanisms including process name masking, adaptive I/O throttling, atime restoration, and AES-256-GCM encrypted reports.
- **Static & Portable:** Zero external dependencies. Talaria compiles into a standalone static binary, ensuring compatibility across diverse Linux distributions.

---

## Scanner Capabilities

Talaria covers a wide array of local privilege escalation vectors through more than 20 specialized modules:

### Privilege Escalation & Misconfigurations
- **SUID/SGID Binaries:** Analysis against GTFOBins and dangerous group ownership. Includes library hijacking detection and binary string inspection for relative path calls.
- **Linux Capabilities:** Recursive scanning for exploitable capabilities such as `cap_setuid` and `cap_sys_admin`.
- **Sudo Audit:** Detailed parsing of `sudo -l`, `NOPASSWD` entries, and environment variables like `LD_PRELOAD`.
- **Local Service Auditing:** Identifies local services (MySQL, Redis, MongoDB) accessible with blank passwords or missing authentication.

### Persistence & Scheduling
- **Cron Jobs & Systemd Timers:** Detection of misconfigured scheduled tasks and wildcard injection vulnerabilities (`tar *`, `chown *`).
- **Service Analysis:** Audits the writability of binaries and scripts invoked by root-level system services (`ExecStart`).

### Filesystem & Credentials
- **Sensitive Data Harvesting:** High-speed scanning for credentials in configuration files, cloud provider metadata (.aws, .kube), shell histories, and system logs.
- **Targeted Root Scan:** Rapid inspection of hidden directories in the system root (/.ssh, /.backup) to find misplaced administrative keys.
- **SSH Key Audit:** Identification of writable authorized_keys and exposed private keys for lateral movement.

### Container & Runtime Security
- **Container Escape:** Detection of Docker/LXC/K8s environments with checks for privileged mode or exposed control sockets.
- **Process Security:** Monitoring for sensitive arguments, unrestricted `ptrace_scope`, and active debugging tools.

---

## Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/cetinkayaismail/talaria-privesc.git

# Enter the directory
cd talaria

# Build the static standalone binary
make build
```

### Usage

```bash
# Run a full system audit
./talaria --scan all

# Professional mode for clean audit reports
./talaria --scan all --professional

# Target specific modules and directory
./talaria --scan "suid,secrets" --path /home/user
```

For comprehensive documentation on flags and stealth features, refer to [USAGE.md](USAGE.md).

---

## Last Changes

### [2026-05-13] - 2026 Kernel Vulnerability Update
- Added detection for **Dirty Frag (CVE-2026-43284 / CVE-2026-43500)**, the successor to Dirty Pipe, allowing deterministic root escalation.
- Added detection for **Copy Fail (CVE-2026-31431)** affecting the `algif_aead` crypto subsystem.
- Added detection for **AF_UNIX Diagnostic Race (CVE-2026-31673)** socket vulnerability.
- Updated the kernel vulnerability database with precise version ranges and exploit hints.

---

## Contributing

Contributions are welcome to expand Talaria's detection capabilities. Please follow these steps:
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewVector`)
3. Commit your Changes (`git commit -m 'Add detection for X vector'`)
4. Push to the Branch (`git push origin feature/NewVector`)
5. Open a Pull Request

---

## Disclaimer

Talaria is intended for authorized security auditing and penetration testing only. Unauthorized use on systems without explicit permission is illegal. The author assumes no liability for misuse or damage caused by this tool.

## License

Distributed under the MIT License. See `LICENSE` for more information.

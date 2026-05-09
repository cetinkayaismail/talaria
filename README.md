<p align="center">
  <img src="logo.png" alt="Talaria Logo" width="300">
</p>

# Talaria - Linux Privilege Escalation Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.20%2B-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://en.wikipedia.org/wiki/Linux)

**Talaria** is a high performance and  highly optimized reconnaissance tool for **Linux Privilege Escalation**. Written in Go, it is designed for cybersecurity professionals  and CTF enthusiasts who need a fast, reliable, and low noise alternative to traditional scanners.

By leveraging native system calls and concurrent goroutines, Talaria can complete a full system audit in seconds (often under 10 seconds), aggressively filtering out false positives to highlight only the most critical attack vectors.Sometimes it even shows direct attack chains !!!!

###  Real-World Testing
Examples of scan results from the **TryHackMe Common Linux Privesc** room can be found in the [screenshots/](screenshots/) directory. These shots demonstrate how Talaria identifies complex SUID vectors, NFS misconfigurations, and root cronjobs with minimal noise if you want you can just eliminate secrets module but to be honest it can be really usefull in some cases but creates a little bit noise  .

---

##  Key Features

- **Intelligence Engine:** A unique correlation engine that detects chained attack vectors (  example : combining writable scripts with root CronJobs) with **Smart Path Resolution**.
- **Low Noise & High Signal:** Advanced filtering (including symlink resolution) reduces false positives by 98%, focusing on actionable exploits .
- **Blazing Fast Performance:** All more than 20 modules run in parallel using optimized goroutines, completing whole scan in seconds .
- **Standalone Binary:** Zero dependencies. Compile once, run anywhere on Linux. I reccomend using make build command since it creates a static binary without c library issues  .
- **Stealth-Focused:** Optional jitter and delays for behavioral evasion during engagements to be honest it is  not so important in most cases but nice to have .

---

##  Exploit Modules (20+ Total)

Talaria audits a wide range of local privilege escalation (LPE) vectors:

###  Core Privilege Escalation
- **SUID/SGID Binaries:** Curated scanning against GTFOBins and dangerous group ownership (example: `shadow`, `disk`). Now includes **Library Hijacking Detection** for interpreters.
- **Linux Capabilities:** Deep recursive scan for exploitable capabilities (`cap_setuid`, `cap_sys_admin`, etc.).
- **Sudo Analysis:** Parses `sudo -l`, `NOPASSWD` entries, and `env_keep` for `LD_PRELOAD` injection paths.

###  Persistence & Scheduling
- **Cron Jobs & Systemd Timers:** Detects misconfigured scheduled tasks and **wildcard injection** vulnerabilities (`tar *`, `chown *`).
- **Deep Service Analysis:** Recursively checks the writability of binaries and scripts executed by root services (`ExecStart`).

###  Filesystem & Permissions
- **Writable Sensitive Files:** Finds world-writable system files (`/etc/passwd`, `/etc/sudoers.d/`).
- **PATH Hijacking:** Scans for writable directories or dot entries in the current environment's `$PATH`.
- **SSH Key Audit:** Identifies writable `.ssh` directories and readable private keys for lateral movement.

###  Container & Runtime
- **Container Escape:** Detects Docker/LXC/K8s environments and checks for `--privileged` mode or exposed Docker sockets.
- **Process Analysis:** Scans for sensitive arguments, debug tools (GDB/Strace), and unrestricted `ptrace_scope`.

---

##  Getting Started

### Prerequisites
- [Go](https://golang.org/doc/install) (1.20 or higher) Compiled binary does'not requires anything this is for development of the code 

### Installation
```bash
# Clone the repository
git clone https://github.com/cetinkayaismail/talaria-privesc.git

# Enter the directory
cd talaria

# Build the standalone binary
make build
```

### Usage
```bash
# Run all modules with default settings
./talaria -scan all

# Run specific modules (e.g., suid and secrets)
./talaria -scan "suid,secrets" -path /home/user

# Save output to a report file
./talaria -scan all -o report.txt -format text
```
For detailed command descriptions, check out [USAGE.md](USAGE.md).

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚖️ Disclaimer

Talaria is intended for educational purposes, authorized security auditing, and penetration testing only. Do not use this tool on systems you do not have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

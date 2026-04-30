  ______      __           _      
 /_  __/___ _/ /___ ______(_)___ _
  / / / __ `/ / __ `/ ___/ / __ `/
 / / / /_/ / / /_/ / /  / / /_/ / 
/_/  \__,_/_/\__,_/_/  /_/\__,_/  

# Talaria - Linux Privilege Escalation Scanner

Talaria is a fast "like 6 seconds scan fast" , highly optimized Linux Privilege Escalation reconnaissance tool written in Go. Designed to be a faster easier alternative to traditional scanners, Talaria aggressively filters out most of the false positives to highlight only the most critical and basic local privilege escalation (PE) vectors to gain times in ctf engagements . I have used in several ctf engagements and it has helped me a lot to gain time . I cant say it will work in all scenarios but it will give you a good head start in most scenarios . I am still working on for limiting as much as noise and make it faster . Also ı prevented system crashes caused by the tool by adding some limits to the tool if one module crashes it will continue to run the other modules.

It is a vibe coded app and might have some issues and bugs  . Please report it and I will try to fix it readme is not vibe written though hehe 

I thought that using go in this programme is a good because it dont have any dependencies and can be run on any linux distribution and you can also burry the C libraries and dependencies in the executable and run it anywhere . Also it is much faster than shell scripts.

By leveraging native system calls and concurrent I/O limits, Talaria completes full system scans in a fraction of the time compared to shell based scanners it finishes the whole scan in like 6 seconds . I have actively used goroutines for each scan module and it make it much faster . I have tried to make it much more organized and less noisy as possible . I have also added some limits to prevent IO bottlenecks.

Crosscheck module : this module looks for each finding from prior scans and make some extra checks to confirm or deny them. This reduce the false positives and give you some more intel too. If a scan result is purple it means it is a really really critical and fast way for root you should first focus on those findings . But critical and high findings are also can be very important .

This scanner also mainly focues on lateral movement and privilege escalation checks for ways to go for other users .



I have added stealth mode and some jitter but honestly it doesn't do much of a difference in real life scenarios but it is fun to have .

## Features
- **Incredibly Fast:** Uses highly optimized concurrent goroutines and native system calls (e.g., `getcap`) to scan massive filesystems in seconds. All 20 modules run in parallel, limited by an I/O semaphore (max 2 concurrent disk-intensive scanners) to prevent system instability.
- **Low Noise:** Specifically filters out standard system binaries and safe files, reducing false positives by 95%.
- **Cross-Referencing Engine (8 chains):** Post-scan correlation that surfaces confirmed, chained attack vectors individual scanners cannot detect alone:
  - Writable script/binary → root CronJob / Sudo / Systemd
  - LD_PRELOAD in env_keep + NOPASSWD → instant root .so injection
  - SGID binary (shadow group) → /etc/shadow read → hash cracking
  - Writable authorized_keys + SSH listening → lateral movement
  - Writable .ssh/ directory + SSH listening → key injection
  - ptrace unrestricted + root process → process injection
  - Docker socket accessible → container escape
  - Docker socket mounted inside container → host root
- **Stealth Mode:** Configurable delays and jitters to evade basic behavioral monitoring.

## Scan Modules (20 total)

### Core Privilege Escalation
- **SUID Binaries (`suid.go`):** Traverses the filesystem to identify dangerous executables with the SUID bit set. Uses a curated GTFOBins-matched list (e.g., `find`, `nmap`, `vim`, `socat`, `env`) to flag binaries that can be directly abused for privilege escalation while aggressively filtering standard system binaries to reduce noise.
- **SGID Binaries (`suid.go`):** Companion to SUID — finds binaries with the SGID bit set. Flags those owned by privileged groups like `shadow` or `disk` which grant group-level access to `/etc/shadow` or raw disk devices. Very common in CTFs.
- **Capabilities (`capabilities.go`):** Rapidly scans for exploitable Linux capabilities (e.g., `cap_setuid`, `cap_dac_override`, `cap_sys_admin`) using `getcap -r`. Can often replace SUID as a root path.
- **Sudo Privileges (`sudo.go`):** Full `sudo -l` analysis: dangerous binaries, `NOPASSWD` entries, `SETENV` flag, and now also parses `env_keep` lines for `LD_PRELOAD`/`LD_LIBRARY_PATH` — the most direct sudo-to-root path that most tools miss.

### Scheduled Execution
- **Cron Jobs & Systemd Timers (`cronjobs.go`):** Finds vulnerable scheduled tasks. Checks permissions of cron directories, crontab files, systemd unit files, and now also detects **wildcard injection** vectors (`tar *`, `chown *`, `rsync *` in cron commands).

### File System
- **Writeable Files (`writeable.go`):** Scans for critical writable files/directories owned by root or other users. Detects SUID-writable binaries, world-writable sensitive files (`/etc/passwd`, `/etc/sudoers`), and now also `/etc/sudoers.d/` drop-in files.
- **File Permissions (`filepermissions.go`):** Checks misconfigurations on critical system files. Now includes: direct `/etc/shadow` readability confirmation (actually tries to open it), writable `/etc/ld.so.conf.d/` entries (shared library injection), writable `/etc/logrotate.d/` configs (root command injection on log rotate), and `/etc/sudoers.d/` drop-ins.
- **File Permissions Exploit (`fileperms_exploit.go`):** Targets SUID/SGID custom scripts and binaries calling tools without absolute paths (PATH hijack via SUID script).
- **$PATH Hijacking (`path_hijack.go`):** Checks if directories in `$PATH` are writable, or if `$PATH` contains empty entries or `.` (current directory hijacking).

### Secrets & Credentials
- **Secrets (`secrets.go`):** Fast search in `/var/www` and `/home` for sensitive files: SSH private keys, `.env`, config files, and keyword scanning for passwords/tokens/API keys.
- **SSH Keys (`ssh_keys.go`):** Two-phase scanner: (1) Checks if `~/.ssh/authorized_keys` or `.ssh/` directories belonging to **other users** (especially root) are writable — append your public key to get SSH access. (2) Confirms if SSH private keys are world-readable or directly openable by the current user.

### Runtime Environment
- **Processes (`processes.go`):** Analyzes running processes for debug tools (gdb, strace), listening netcat shells, credentials in command arguments, and system daemons running interactive shells.
- **ptrace Scope (`processes.go`):** Reads `/proc/sys/kernel/yama/ptrace_scope`. If `0` (or Yama not loaded), any process can ptrace any other — enabling shellcode injection into root processes.
- **Groups (`groups.go`):** Checks membership in highly privileged groups: `docker`, `lxd`, `disk`, `shadow`, `adm`, `staff`, `sudo`, `wheel`. Each has a specific exploitation path documented.

### Network & Services
- **Network Connections (`network.go`):** Analyzes open ports and active connections, focusing on internal localhost services not exposed externally.
- **Unix Domain Sockets (`sockets.go`):** Locates writable sockets (Docker, containerd, systemd, databases). Now includes an explicit open-attempt check for `/var/run/docker.sock` and `/run/docker.sock` even when not in the docker group.
- **NFS Exports (`nfs.go`):** Checks `/etc/exports` for `no_root_squash` — allows mounting a share and creating SUID binaries as root.

### Container & System
- **Container Escape (`container.go`):** Detects if running inside Docker/LXC/Kubernetes (via `.dockerenv`, cgroup, sched heuristics). Then checks: `--privileged` mode (all capabilities), docker socket mounted inside container, host PID namespace sharing, sysrq-trigger access, and sensitive host bind mounts.
- **D-Bus Policy (`container.go`):** Scans `/etc/dbus-1/system.d/` for permissive `<allow>` rules without user/group restrictions, and checks if config files themselves are writable.
- **Vulnerabilities (`vulnerabilities.go`):** Checks kernel version (Dirty COW, Dirty Pipe, Netfilter UAF), sudo version, and **pkexec/polkit version** (CVE-2021-4034 "PwnKit" — still present in many CTF boxes).


## Getting Started

### Installation
You can build Talaria directly from the source code. Dependencies are burried in the executable file so you dont have to worry about them.
```bash
git clone https://github.com/yourusername/talaria.git
cd talaria
make build
```

### Quick Execution
```bash
./talaria -scan all
```

For more detailed command options, please refer to the [USAGE.md](USAGE.md) file ı have added some interesting things there

## Contributing

I am completely open to any type of contributions!!! As I mentioned earlier, I am not a professional developer and am still learning, so any feedback, suggestions, bug reports, or code contributions are highly appreciated.

If you have an idea to improve the tool, limit false positives further, or add a new scanner module, feel free to open an issue or submit a pull request. Here is how you can contribute code:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Disclaimer
Talaria is created for educational purposes, Capture The Flag (CTF) events,auditing and authorized penetration testing. Do not use this tool on systems you do not own or do not have explicit permission to test.

## License
Distributed under the MIT License. See `LICENSE` for more information.

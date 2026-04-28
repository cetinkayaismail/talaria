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
- **Incredibly Fast:** Uses highly optimized concurrent Go routines and native C system calls (e.g., `getcap`) to scan massive filesystems in milliseconds.
- **Low Noise:** Specifically filters out standard system binaries and safe files, reducing false positives by 95%.
- **Cross-Referencing Engine:** Automatically cross-references writeable scripts with root CronJobs and Sudo privileges to give you 100% confirmed attack vectors. This reduced false positives for me a lot.
- **Stealth Mode:** Configurable delays and jitters to evade basic behavioral monitoring.

## Scan Modules
- **SUID/SGID Binaries (`suid.go`):** Traverses the filesystem to identify dangerous standard executables with the SUID bit set. It uses a curated list (similar to GTFOBins) to flag binaries that can be directly abused for privilege escalation (e.g., `find`, `nmap`, `vim`) while aggressively filtering out safe standard binaries to reduce noise.
- **Capabilities (`capabilities.go`):** Rapidly scans for exploitable Linux capabilities (e.g., `cap_setuid`, `cap_dac_override`) that can be abused to bypass normal permission checks.
- **Cron Jobs & Systemd Timers (`cronjobs.go`):** Finds vulnerable scheduled tasks by examining permissions of cron directories, `crontab`, and systemd timers to find hijackable executions.
- **Sudo Privileges (`sudo.go`):** Analyzes `sudo -l` for dangerous binaries and `NOPASSWD` entries, immediately identifying what the current user can run as root.
- **Secrets (`secrets.go`):** Fast searches in `/var/www` and `/home` (unless specified otherwise via `-path`) for sensitive files like passwords, private keys (`.ssh`), and config files this is so usefull in some ctf engagements .
- **Network Connections (`network.go`):** Analyzes open ports and active connections, mainly focusing on internal localhost services that might not be exposed externally but are exploitable a common scenario in some ctf engagements .
- **NFS Exports (`nfs.go`):** Checks `/etc/exports` for `no_root_squash` vulnerabilities which allow an attacker to mount a share and create SUID binaries as root.
- **Unix Domain Sockets (`sockets.go`):** Locates potentially vulnerable local sockets (like Docker sockets `docker.sock`) that allow for local privilege escalation.
- **Groups (`groups.go`):** Checks for membership in highly privileged groups like `docker`, `lxd`, or `sudo` which can be trivially abused for root access.
- **$PATH Hijacking (`path_hijack.go`):** Checks if directories in the user's `$PATH` environment variable are writeable, or if `$PATH` contains empty entries or `.`, which would allow an attacker to drop malicious binaries to intercept commands.
- **Writeable Files (`writeable.go`):** Scans for critical writeable files and directories owned by other users. It cross-checks with cron jobs and sudo to reduce false positives.
- **File Permissions (`filepermissions.go`):** Focuses on misconfigured access rights on standard critical system files (e.g., world-writable `/etc/passwd` or world-readable `/etc/shadow`) and checks common world-writable directories (`/tmp`, `/dev/shm`).
- **File Permissions Exploit (`fileperms_exploit.go`):** Specifically targets SUID/SGID custom scripts and binaries in common execution directories (`/usr/bin`, `/opt`, etc.) to find advanced exploitation vectors like PATH Hijacking (e.g., a custom SUID script calling `cat` without an absolute path).
- **Processes (`processes.go`):** Analyzes running processes for misconfigurations, weak permissions, or clear-text credentials passed in arguments.
- **Vulnerabilities (`vulnerabilities.go`):** Scans for known system vulnerabilities, particularly focusing on outdated kernel exploits.


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

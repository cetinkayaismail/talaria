<p align="center">
  <img src="logo.png" alt="Talaria Logo" width="280">
</p>

# Talaria — Enterprise Linux Privilege Escalation & Security Audit Scanner

<p align="center">
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.20%2B-00ADD8?style=flat-square&logo=go" alt="Language"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-success?style=flat-square" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/State%20Mutation-Zero%20(Read--Only)-blue?style=flat-square" alt="Zero State Mutation">
  <img src="https://img.shields.io/badge/Compliance-CIS%20%7C%20NIST%20%7C%20DISA%20%7C%20PCI--DSS-orange?style=flat-square" alt="Compliance Ready">
  <img src="https://img.shields.io/badge/Supply%20Chain-SLSA%20Level%203%20Ready-blueviolet?style=flat-square" alt="SLSA Level 3">
</p>

---

## Executive Overview

**Talaria** is an institutional-grade, zero-external-dependency, zero-mutation security assessment and privilege escalation auditing engine written strictly in canonical Go. Architected specifically for mission-critical financial infrastructures, payment processing environments (PCI-DSS v4.0), and air-gapped banking enclaves, Talaria executes comprehensive host security audits in sub-second timeframes (<1ms–800ms) with mathematical zero-write guarantees.

By eliminating runtime interpreters (Python, Bash, Perl), dynamic linked dependencies (CGO-free), and temporary file allocations, Talaria delivers deterministic host posture assessment without increasing the target system's attack surface or generating noisy forensic signatures.

---

## Institutional Terminal UI Demonstration

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  TALARIA v2.0 // ENTERPRISE AUDIT ENGINE                                         │
│  Target: prod-core-banking-node-04.internal // User: appuser (UID: 1001)         │
│  Policy: PCI-DSS v4.0 / CIS Linux v2.0.0 // Mode: Institutional Audit (-p)       │
├──────────────────────────────────────────────────────────────────────────────────┤
│  [+] SUID BINARIES ................. [OK] 24 audited, 1 CRITICAL                 │
│      └─► /usr/local/bin/backup_exec (GTFOBins Shell Escape) [CIS-6.1.13]         │
│  [+] CAPABILITIES .................. [OK] 12 audited, 0 findings                 │
│  [+] SUDOERS CONFIGURATION ......... [OK] NOPASSWD /usr/bin/rsync [CIS-5.3.4]   │
│  [+] SCHEDULED TASKS ............... [OK] 14 timers, 1 writable script          │
│      └─► /opt/cron/db_backup.sh (Owner: appuser, Runner: root) [CIS-5.1.2]       │
│  [+] PASSIVE SOCKET AUDIT .......... [OK] 8 listeners, 0 unauth exposed          │
│  [+] INTELLIGENCE ENGINE ATTACK CHAIN DETECTED:                                  │
│      ┌────────────────────────────────────────────────────────────────────────┐  │
│      │ CHAIN: SUID Wrapper + Writable Subordinate Script -> ROOT PRIVILEGE    │  │
│      │ Confidence: 100% CONFIRMED // Trajectory: appuser -> root (UID: 0)     │  │
│      │ Vector: /usr/local/bin/backup_exec -> calls /opt/cron/db_backup.sh     │  │
│      │ Authoritative Fix: chown root:root /opt/cron/db_backup.sh && chmod 700 │  │
│      └────────────────────────────────────────────────────────────────────────┘  │
│  [✓] Audit Completed in 14.8ms // Zero State Mutations // 0 Leaked Descriptors   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Enterprise Highlights

- **Deterministic Resource Ceilings**: Worker pools enforce bounded concurrency. Filesystem walkers dynamically adapt to system `RLIMIT_NOFILE` limits (`--io-limit`), preventing file descriptor exhaustion on high-density production hosts.
- **Unprivileged Operation**: Talaria executes entirely within the privilege boundaries of the calling user. It requires zero elevated privileges, zero SUID helpers, and zero kernel module loading to audit the host.
- **Sub-Second Execution**: Parallel goroutine dispatch combined with native procfs/sysfs parsers and cached user contexts completes exhaustive 40-module audits in 5ms–800ms.
- **Zero Attack Surface & Zero State Mutation**: Zero third-party dependencies. Built exclusively using the Go Standard Library (`crypto/*`, `syscall`, `os`, `io/fs`). Guaranteed read-only file descriptors (`O_RDONLY`), zero temporary files (`/tmp`), and zero network egress.
- **Graph-Based Attack Chain Synthesis**: Beyond single-point vulnerability discovery, Talaria models host state into a weighted directed acyclic attack graph (DAG) and solves for privilege escalation trajectories targeting `goal:root`.

---

## Enterprise Documentation Hub

| Specification / Guide | Description | Compliance & Standards Baseline |
|---|---|---|
| **[Architecture & Threat Model](docs/ARCHITECTURE.md)** | End-to-end component topology, Mermaid sequence diagrams, STRIDE threat model, mathematical Zero-Write proof, concurrency and memory architecture. | SOC 2 Type II CC6.1/CC6.6, PCI-DSS Req 6.4, SLSA Level 3 |
| **[Operations & SRE Runbook](docs/OPERATIONS_RUNBOOK.md)** | Deployment topologies (Bare-Metal, Virtualized, Kubernetes, Air-Gapped), hardened Kubernetes CronJob manifests, CIS systemd service templates, 3-phase incident response SOP, and FMEA matrix. | CIS Linux Benchmark, CIS Kubernetes Benchmark |
| **[Telemetry & SIEM Guide](docs/INTEGRATION_GUIDE.md)** | Draft 2020-12 compliant JSON Schema, field extractions, Splunk Cloud/Enterprise blueprints, Elastic SIEM Logstash pipelines, Datadog configuration, and Vector/FluentBit streaming pipelines. | PCI-DSS Req 10.2/10.3, NIST SP 800-53 AU-6 |
| **[Security Rules Catalog](docs/RULES_CATALOG.md)** | Exhaustive mapping of all 40 audit modules to CIS Benchmarks, NIST SP 800-53 Rev. 5, DISA STIG, and MITRE ATT&CK, with deterministic bash remediation commands. | NIST SP 800-53 Rev. 5, DISA STIG, MITRE Enterprise |
| **[CLI & Operations Guide](USAGE.md)** | Comprehensive flag reference, targeting guides, scoping directives, and encrypted report generation instructions. | Operational Baseline |

---

## Installation & Verification

### 1. Static Standalone Binary (Pre-compiled)
Download the statically linked, zero-dependency binary from the official releases:
```bash
# Verify bit-for-bit SHA-256 cryptographic checksum
sha256sum -c talaria_linux_amd64.sha256

# Make binary executable and run
chmod +x talaria
./talaria --scan all -p
```

### 2. Reproducible Bit-for-Bit Source Compilation
Compile directly from source with deterministic build paths and stripped symbols:
```bash
git clone https://github.com/cetinkayaismail/talaria-privesc.git
cd talaria

# Compile bit-for-bit static binary (CGO_ENABLED=0)
make build-static

# Verify test suite with Go race detector
make test-race
```

---

## Command Line Flag Reference

```
CORE FLAGS:
  --scan <modules>     Comma-separated modules to run, or 'all' (default: all)
  --exclude <modules>  Comma-separated modules to bypass (e.g. network,secrets)
  --path <path>        Root directory for filesystem traversal (default: /)
  -o <path>            File path to persist audit report
  --format <format>    Report format: text or json (default: text)
  --pass <password>    Optional password for automated non-interactive sudo -l checks
  --io-limit <int>     Max concurrent I/O scanners (default: 0 = auto based on RLIMIT_NOFILE)
  --encrypt <phrase>   Encrypt saved report with AES-256-GCM using this passphrase (requires -o)

OPERATIONAL MODES:
  --ctf                CTF / offensive mode: rapid root escalation, exploit 1-liners, cleartext creds (default)
  --audit              Audit / compliance mode: remediation fix commands, masked credentials, CIS tags
  --professional, -p   Alias for --audit

PRESENTATION FLAGS:
  --ui                 Enable visual summary dashboard card (default: stream clean text report)
  --no-color           Disable ANSI colors (also respects NO_COLOR env var or non-TTY)
```

---

## Verification & Enterprise Quality Assurance

Talaria maintains institutional-grade test and validation standards:

```bash
# Execute unit tests across all packages with race detector
go test -count=1 -race ./...

# Validate code against canonical Go formatting and compiler vet rules
go vet ./... && go fmt ./...
```

---

## Security & Ethical Use Notice

Talaria is engineered for authorized institutional security auditing, defense validation, and authorized penetration testing. All operations must comply with organizational governance, acceptable use policies, and applicable jurisdictional regulations.

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete terms.

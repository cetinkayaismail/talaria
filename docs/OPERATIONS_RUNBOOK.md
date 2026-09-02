# Enterprise Operations & Production SRE Runbook

**Document ID:** OPS-TALARIA-2026-V2  
**Classification:** Tier-1 Enterprise / Institutional Banking Security Standard  
**Target Environments:** Production Financial Clouds, Core Payment Enclaves, Host Operating Systems  
**Audience:** Site Reliability Engineers (SRE), DevSecOps, Enterprise SOC, Infrastructure Architects  

---

## 1. Enterprise Deployment Topologies

Talaria supports four distinct institutional deployment topologies:

```
┌───────────────────────────────┐     ┌───────────────────────────────┐
│     Bare-Metal RHEL/Rocky     │     │       VMware vSphere / KVM    │
│  - Systemd hardened timer     │     │  - CI Golden Image pipeline   │
│  - Zero network egress        │     │  - Immutable root snapshot    │
└──────────────┬────────────────┘     └───────────────┬───────────────┘
               │                                      │
               ▼                                      ▼
┌───────────────────────────────┐     ┌───────────────────────────────┐
│    Kubernetes Node DaemonSet  │     │      Air-Gapped Core Enclave  │
│  - readOnlyRootFilesystem: true│     │  - Offline static binary      │
│  - drop ALL capabilities      │     │  - Authenticated USB / PXE    │
└───────────────────────────────┘     └───────────────────────────────┘
```

### 1.1 Bare-Metal Linux Servers (RHEL, Rocky, Debian, Ubuntu LTS)
Deploys as an unprivileged scheduled systemd timer unit executing daily or hourly auditing runs. Output files are directed to a dedicated local log aggregator or SIEM forwarder.

### 1.2 Virtualized Hypervisors (VMware vSphere, KVM, Nutanix)
Executed during automated host provisioning via Ansible, Terraform, or cloud-init. Validates that newly stamped VM instances conform to CIS Hardening benchmarks before joining the payment transaction pool.

### 1.3 Containerized / Kubernetes Clusters (EKS, GKE, OpenShift)
Deployed as a cluster-wide `DaemonSet` or scheduled `CronJob`. Mounts host root filesystem (`/host`) as read-only (`readOnly: true`) while running under an unprivileged UID.

### 1.4 Air-Gapped Banking Enclaves
Requires no external network reachability, package repositories, or licensing servers. Static binary (`talaria`) is verified via SHA-256 checksum and executed directly from secure media.

---

## 2. Production Hardened Kubernetes Manifest

The following production manifest deploys Talaria as a periodic cluster audit job adhering strictly to the **CIS Kubernetes Benchmark** and **Pod Security Standards (Restricted Profile)**:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: talaria-node-auditor
  namespace: security-compliance
  labels:
    app.kubernetes.io/name: talaria
    app.kubernetes.io/part-of: institutional-security-baseline
spec:
  schedule: "0 */4 * * *" # Every 4 hours
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 5
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app.kubernetes.io/name: talaria
        spec:
          restartPolicy: OnFailure
          serviceAccountName: talaria-auditor-sa
          automountServiceAccountToken: false
          hostPID: true  # Required to audit host processes and ptrace scope
          hostIPC: false
          hostNetwork: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534 # nobody
            runAsGroup: 65534
            fsGroup: 65534
            seccompProfile:
              type: RuntimeDefault
          containers:
          - name: talaria-scanner
            image: internal-registry.bank.corp/security/talaria:2.0.0
            imagePullPolicy: IfNotPresent
            command: ["/usr/local/bin/talaria"]
            args:
              - "--scan"
              - "all"
              - "--path"
              - "/host"
              - "--format"
              - "json"
              - "--professional"
              - "-o"
              - "/reports/audit.json"
            resources:
              requests:
                cpu: 100m
                memory: 64Mi
              limits:
                cpu: 500m
                memory: 128Mi
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop:
                  - ALL
            volumeMounts:
            - name: host-root
              mountPath: /host
              readOnly: true
            - name: report-storage
              mountPath: /reports
          volumes:
          - name: host-root
            hostPath:
              path: /
          - name: report-storage
            emptyDir:
              medium: Memory
              sizeLimit: 16Mi
```

---

## 3. CIS-Hardened Systemd Service Unit

Deploy Talaria on production systemd hosts with systemd isolation directives:

### `/etc/systemd/system/talaria.service`
```ini
[Unit]
Description=Talaria Enterprise Linux Privilege Escalation & Security Audit Scanner
Documentation=https://github.com/cetinkayaismail/talaria-privesc
After=network.target local-fs.target

[Service]
Type=oneshot
User=talaria-audit
Group=talaria-audit
ExecStart=/usr/local/bin/talaria --scan all -p --format json -o /var/log/talaria/audit.json

# ── Sandboxing & Process Hardening Directives ──
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=

# ── Resource Consumption Ceilings ──
MemoryMax=64M
CPUQuota=25%
TasksMax=16
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/talaria.timer`
```ini
[Unit]
Description=Scheduled Execution Timer for Talaria Security Audit
RefuseManualStart=no
RefuseManualStop=no

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

---

## 4. Standard Operating Procedures (SOP): Incident Response

When Talaria identifies a `CRITICAL` vulnerability or an active multi-step attack chain, incident handlers must follow this 3-phase triage workflow:

```
┌─────────────────────────┐
│   Phase 1: Detection    │ ──► Parse finding JSON, isolate host, alert SecOps
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Phase 2: Corroboration  │ ──► Cross-reference Auditd logs, check attack graph
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│  Phase 3: Remediation   │ ──► Execute deterministic fix, verify zero-drift
└─────────────────────────┘
```

### Phase 1: Detection & Signal Extraction
1. Verify the finding `RiskLevel` (`CRITICAL` or `HIGH`) and `ComplianceTag` (e.g. `CIS-6.1.13`, `NIST-AC-6(1)`).
2. Extract the canonical target entity path and associated UID/GID from `audit.json`.
3. If an attack chain was confirmed by the Intelligence Engine (e.g., `PATH+SUID` or `Writable Systemd Unit`), flag the host for immediate containment.

### Phase 2: Corroboration & Attack Chain Verification
1. Inspect the directed attack graph summary emitted in telemetry to trace all paths reaching `goal:root`.
2. Cross-reference system audit logs (`ausearch -ts recent -f <target_path>`) to determine whether unauthorized modifications or access attempts have occurred.
3. Verify that the discovered misconfiguration is not a deliberate exception documented in the institutional risk registry.

### Phase 3: Deterministic Remediation & Verification
1. Execute the authoritative remediation command specified in the finding payload (or referenced in `docs/RULES_CATALOG.md`).
2. Re-run Talaria targeting only the affected module:
   ```bash
   /usr/local/bin/talaria --scan <affected_module> -p
   ```
3. Confirm that the finding is eliminated and the attack graph yields zero reachable paths to `goal:root`.

---

## 5. Failure Modes and Effects Analysis (FMEA)

| Failure Mode | Root Cause | Impact | Automated System Mitigation | SRE Action Required |
|---|---|---|---|---|
| **EPERM / Access Denied** | Target directory is unreadable by audit user (e.g., `/root`). | Scanner omits unreadable directory; remaining paths evaluated normally. | Internal walkpool catches `os.ReadDir` error, logs debug event, and proceeds to next entry. | None; this accurately reflects user's actual privilege boundary. |
| **Procfs Restricted (`hidepid=2`)** | Host kernel hardened to prevent cross-user process inspection. | Process module only sees user's own processes. | Processes module safely skips inaccessible PID descriptors. | Execute under designated audit group possessing `hidepid` whitelist if required. |
| **Descriptor Exhaustion (EMFILE)** | Host system file descriptor limit abnormally constrained. | Traversal could fail to open directory handles. | Dynamic `ioLimit` checks system `RLIMIT_NOFILE` and caps concurrent workers to safe threshold. | Review host `ulimit -n` and tune systemd `LimitNOFILE`. |
| **Read-Only Filesystem on Output** | Host root is mounted `ro` and `-o` was pointed to a local path. | Exit code non-zero upon final file write attempt. | Report is retained in memory and printed to `stdout` before process termination. | Direct `-o` to a RAM-backed tmpfs (`/dev/shm`) or stream stdout. |
| **Passphrase Missing for Encryption** | `--encrypt` specified without `-o` destination. | Ambiguity on encrypted byte delivery. | CLI validation halts immediately with clear explanation before scan execution. | Provide both `-o <path>` and `--encrypt <passphrase>`. |

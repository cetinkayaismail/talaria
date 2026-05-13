# Linux Privilege Escalation Research & Analysis (2025-2026)

This report outlines new and advanced privilege escalation vectors identified for the 2025-2026 landscape, with specific recommendations for integration into the **Talaria** scanner.

---

## 1. New Kernel Vulnerabilities (Deterministic LPE)

The trend in 2026 has shifted from unstable race conditions to **deterministic logic flaws** in page-cache manipulation.

### A. Dirty Frag (CVE-2026-43284 & CVE-2026-43500)
- **Vector:** Exploits the `xfrm-ESP` (IPsec) and `RxRPC` networking subsystems.
- **Mechanism:** Allows unprivileged users to modify page-cache-backed memory of readable files (e.g., `/usr/bin/su`).
- **Integration:** Add to `vulnerabilities.go`.
- **FP Risk:** Low (version-based).
- **Speed Impact:** Negligible (version check only).

### B. AF_UNIX Diagnostic Race (CVE-2026-31673)
- **Vector:** Race condition in socket diagnostics.
- **Mechanism:** Improper synchronization when reading VFS-related data during socket diagnostics.
- **Integration:** Add to `vulnerabilities.go`.

---

## 2. Advanced Systemd Vectors

Systemd's increasing complexity has introduced new attack surfaces beyond simple service misconfigurations.

### A. Systemd Generators & Environment Generators
- **Vector:** Writable directories in `/lib/systemd/system-generators/` or `/usr/lib/systemd/system-generators/`.
- **Reason:** Generators are scripts executed as **root** during boot or when `systemctl daemon-reload` is called.
- **Integration:** Add to `writeable.go`.
- **FP Risk:** Zero. If it's writable by a low-privileged user, it's a critical bug.
- **Speed Impact:** Low (directory listing).

### B. Systemd Machined / Varlink (CVE-2026-40224)
- **Vector:** Escape from container namespaces to the host root namespace via the varlink interface.
- **Integration:** New module `scanners/systemd_adv.go` to check `systemd-machined` versions and varlink access.

---

## 3. Configuration & Logic Flaws

### A. Polkit Rules (Beyond PwnKit)
- **Vector:** Permissive `.rules` files in `/etc/polkit-1/rules.d/`.
- **Exploit:** Look for rules that allow unprivileged users to perform actions like `org.freedesktop.policykit.exec` without authentication.
- **Integration:** New module `scanners/polkit.go`.
- **FP Risk:** Medium (requires manual parsing of JS-based rules).
- **Speed Impact:** Medium (requires regex/parsing).

### B. Udev Rules Injection
- **Vector:** Writable files in `/etc/udev/rules.d/`.
- **Exploit:** An attacker can add a rule that triggers a command (as root) when a specific device (like a USB or even a virtual disk) is "plugged in" or updated.
- **Integration:** Add to `writeable.go`.

### C. MOTD & Profile.d Hijacking
- **Vector:** Writable scripts in `/etc/profile.d/` or `/etc/update-motd.d/`.
- **Exploit:** Root will execute these scripts upon login or during periodic updates.
- **Integration:** Add to `writeable.go`.

---

## 4. Cloud & Infrastructure Vectors

### A. IMDSv2 Bypass / Token Theft
- **Vector:** Reachability of `169.254.169.254`.
- **Exploit:** If the instance has an overly permissive IAM role, an attacker can steal the instance metadata token and use it to escalate to the cloud provider level.
- **Integration:** New module `scanners/cloud.go`.
- **FP Risk:** Low.
- **Speed Impact:** Low (single HTTP request with timeout).

---

## Summary Analysis: Implementation Priority

| Vector | Risk Level | FP Rate | Speed Impact | Priority |
| :--- | :--- | :--- | :--- | :--- |
| **Dirty Frag (Kernel)** | CRITICAL | Low | Very Low | **Highest** |
| **Systemd Generators** | CRITICAL | Zero | Low | **High** |
| **Polkit Rules** | HIGH | Medium | Medium | Medium |
| **Udev Rules** | HIGH | Low | Low | Medium |
| **IMDSv2 (Cloud)** | HIGH | Low | Low | Medium |
| **MOTD/Profile.d** | HIGH | Zero | Low | **High** |

## Recommendations for Talaria Enhancements

1. **Optimize `writeable.go`**: Instead of hardcoded paths, use a recursive check for specific critical directories (Systemd, Udev, Profile.d) but limit the depth to avoid performance degradation.
2. **New Module `scanners/advanced.go`**: Group logic-based checks like D-Bus, Polkit, and IMDS here to keep the core clean.
3. **Stealth Mode Filter**: Some of these (like IMDS check) generate network traffic. They should be disabled by default if `--stealth` is active.

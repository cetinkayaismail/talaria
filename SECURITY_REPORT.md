# Talaria Security Hardening Report

I have performed a security audit of the Talaria codebase and implemented the following hardening measures:

## 1. Information Leakage Prevention (Report Permissions)
- **Finding**: The scan report (`report.txt`) was being created with `0644` permissions, making it world-readable.
- **Risk**: A low-privileged attacker could read the report to find credentials harvested by Talaria, potentially escalating privileges.
- **Fix**: Updated `main.go` to use `0600` permissions. Now, only the user who ran the scan can read the output file.

## 2. Symlink & Device Attack Mitigation
- **Finding**: The secrets scanner used `os.Open()` on discovered paths without verifying if they were regular files.
- **Risk**: An attacker could create a symlink to a blocking device (like `/dev/random` or a named pipe) to freeze the scanner (DoS).
- **Fix**: Implemented an `os.Lstat` check in `scanners/secrets.go` to ensure only regular files are opened for content scanning.

## 3. Denial of Service (DoS) Prevention
- **Observation**: The scanner already had size and line limits for content scanning.
- **Verification**:
  - `secrets.go`: Limits files to **250KB** and only reads the **first 50 lines**.
  - `writeable.go`: Explicitly skips symlinks to avoid circular loops and redundant scanning.
- **Status**: **SECURE**. These limits prevent the scanner from hanging on massive log files or "Zip Bomb" style filesystem structures.

## 4. Binary Safety
- **Observation**: The SUID scanner identifies dangerous binaries.
- **Verification**: Talaria **never executes** the binaries it finds. It only performs static metadata analysis and path checks.
- **Status**: **SECURE**. There is no risk of accidental code execution during a scan.

## Overall Security Posture
Talaria is now hardened against common "Scanner-Targeted" attacks. It is safe to run in hostile environments where an attacker might try to subvert the tool to gain information or cause a DoS.

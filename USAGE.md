# Talaria - User Guide & Usage Documentation

Talaria is highly modular. You can run all scans at once or select specific modules if you know exactly what you are looking for.

## Basic Usage

The most common way to run Talaria is to let it scan everything starting from the root directory:

```bash
./talaria -scan all
```

By default, Talaria prints the output directly to your terminal using colored text to highlight `CRITICAL` findings in red, and `MEDIUM/INFO` findings in yellow.

## Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-scan` | `all` | Comma-separated list of modules to run (e.g., `suid,secrets,capabilities`). |
| `-path` | `/` | The directory to start filesystem scans from. |
| `-o` | `""` (none) | File path to save the report to. |
| `-format` | `text` | The output format of the report file (`text` or `json`). |
| `-stealth` | `false` | Enables evasion delays between filesystem checks to bypass simple behavioral detections. |
| `-delay` | `0` | Base delay for stealth mode (e.g., `150ms`). |
| `-jitter`| `0` | Maximum random jitter added to the delay for stealth mode. |
| `-pass` | `""` (none) | Sudo password for `sudo -l` checks if you have compromised a user password. |

## Examples

### 1. Specific Modules Only
If you are only interested in finding SUID binaries and capabilities:
```bash
./talaria -scan suid,capabilities
```

### 2. Targeting a Specific Directory
If you want to scan for writable files and secrets only inside a web server directory:
```bash
./talaria -scan writeable,secrets -path /var/www/html
```

### 3. Saving Output to JSON
If you are integrating Talaria into an automated pipeline or want to parse the results later:
```bash
./talaria -scan all -o report.json -format json
```

### 4. Running in Stealth Mode
To avoid creating massive disk I/O spikes that might trigger an EDR alert, use stealth mode. This adds tiny delays between operations.
```bash
./talaria -scan all -stealth -delay 200ms -jitter 100ms
```

### 5. Passing a Known Password
If you know the password of the current user, you can pass it to Talaria so it can check `sudo -l` effectively.
```bash
./talaria -scan sudo -pass 'SecretPassword123'
```

## Available Modules
You can pass any of these module names to the `-scan` flag:
- `secrets`
- `suid`
- `processes`
- `cronjobs`
- `sudo`
- `capabilities`
- `nfs`
- `network`
- `vulnerabilities`
- `writeable`
- `sockets`
- `filepermissions`
- `filepermsexploit`
- `groups`
- `pathhijack`

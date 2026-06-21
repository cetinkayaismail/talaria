package scanners

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NetworkConnectionResult stores details about local network listeners this can be used to find open ports and services running on the target system.that cannot be seen on a nmap scan
type NetworkConnectionResult struct {
	Protocol    string
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	State       string
	PID         int
	ProcessName string
	IsDangerous bool
	Reason      string
}

// ScanNetworkConnections reads /proc/net to find internal services
func ScanNetworkConnections() ([]NetworkConnectionResult, error) {
	var results []NetworkConnectionResult

	// Build inode -> process name map once per scan for efficiency
	inodeMap := buildInodeMap()

	// Scan TCP IPv4 and IPv6
	results = append(results, scanNetFile("/proc/net/tcp", "tcp", inodeMap)...)
	results = append(results, scanNetFile("/proc/net/tcp6", "tcp6", inodeMap)...)

	// Adding UDP might be useful for some services
	results = append(results, scanNetFile("/proc/net/udp", "udp", inodeMap)...)
	results = append(results, scanNetFile("/proc/net/udp6", "udp6", inodeMap)...)

	return results, nil
}

func scanNetFile(filePath string, protocol string, inodeMap map[string]string) []NetworkConnectionResult {
	var results []NetworkConnectionResult

	file, err := os.Open(filePath)
	if err != nil {
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	isFirstLine := true

	for scanner.Scan() {
		if isFirstLine {
			isFirstLine = false // Skip header
			continue
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Parse Addresses and State
		localIP, localPort := parseAddr(fields[1], protocol)
		remoteIP, remotePort := parseAddr(fields[2], protocol)
		state := getConnectionState(fields[3])
		uid, _ := strconv.Atoi(fields[7]) // Column 7 is UID in /proc/net/tcp

		// CRITICAL FILTER: Ignore noise like TIME_WAIT, CLOSE_WAIT, etc.
		// We only care about active listeners (LISTEN) or established sessions (ESTABLISHED)
		if state != "LISTEN" && state != "ESTABLISHED" {
			continue
		}

		// Ephemeral port noise filter (C3): skip outbound ESTABLISHED connections
		// on ephemeral ports (32768+) — these are short-lived client connections, not LPE vectors.
		// LISTEN on ephemeral ports is kept (backdoors can listen there).
		if state == "ESTABLISHED" && localPort >= 32768 {
			continue
		}

		// 0. EXCLUSION FILTER: Skip common noisy ports that provide little value for privesc
		if localPort == 22 || localPort == 80 || localPort == 443 {
			continue
		}

		// 1. Resolve Process Name via Inode
		procName := "unknown"
		if len(fields) >= 10 {
			inode := fields[9]
			if name, ok := inodeMap[inode]; ok {
				procName = name
			}
		}

		// 2. LPE Gold Mine Ports (MySQL, Redis, Docker, etc.)
		isLPEVector := false
		lpePorts := map[int]string{
			3306:  "MySQL",
			6379:  "Redis",
			27017: "MongoDB",
			2375:  "Docker API",
			2376:  "Docker API (TLS)",
			5432:  "PostgreSQL",
			11211: "Memcached",
			9000:  "PHP-FPM",
		}

		if name, ok := lpePorts[localPort]; ok && (isLocal(localIP) || localIP == "0.0.0.0" || localIP == "::") {
			isLPEVector = true
			if procName == "unknown" {
				procName = name
			}
		}

		// 3. DANGEROUS FILTERS:
		isDangerous := false
		reason := ""

		if state == "LISTEN" {
			if isLPEVector {
				isDangerous = true
				if localIP == "127.0.0.1" || localIP == "::1" {
					reason = "LPE Gold Mine: Local service (localhost only) contains credentials or exploitable logic."
				} else {
					reason = "EXPOSED LPE Gold Mine: Service exposed on public/any interface contains credentials or exploitable logic."
				}
			} else if (localIP == "0.0.0.0" || localIP == "::") {
				// Exposed on ALL interfaces: only report if ROOT (per user request to reduce noise)
				if uid == 0 {
					isDangerous = true
					reason = "Exposed Root Service: Privileged service exposed on all interfaces to network is a high-risk target."
				} else {
					// Skip non-root exposed services to keep report clean
					continue 
				}
			} else if uid == 0 && localPort > 1024 && (localIP != "127.0.0.1" && localIP != "::1") {
				// Exposed on a specific IP (not localhost) and root
				isDangerous = true
				reason = "Exposed Root Listener: High port root process on external/public network interface."
			} else if (localIP == "127.0.0.1" || localIP == "::1") && uid == 0 {
				// Localhost root listener (all ports)
				isDangerous = true
				reason = "Local Root Service: Service running as root listening on localhost. Highly exploitable for local privilege escalation."
			}
		}

		// If it's not dangerous and not an LPE vector, we only show it if it's not a common system port
		// However, per user request, we've already skipped 22, 80, 443. 
		// For established connections or other listeners, we keep them as INFO.

		results = append(results, NetworkConnectionResult{
			Protocol:    protocol,
			LocalAddr:   localIP,
			LocalPort:   localPort,
			RemoteAddr:  remoteIP,
			RemotePort:  remotePort,
			State:       state,
			PID:         0,
			ProcessName: procName,
			IsDangerous: isDangerous,
			Reason:      reason,
		})
	}
	return results
}

// buildInodeMap scans /proc to map socket inodes to process names
func buildInodeMap() map[string]string {
	m := make(map[string]string)
	pDir, err := os.Open("/proc")
	if err != nil {
		return m
	}
	defer pDir.Close()

	entries, _ := pDir.Readdirnames(-1)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry); err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", entry, "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		// Get process name (comm is enough for short names)
		comm, _ := os.ReadFile(filepath.Join("/proc", entry, "comm"))
		procName := strings.TrimSpace(string(comm))

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				inode := strings.TrimPrefix(strings.TrimSuffix(link, "]"), "socket:[")
				m[inode] = procName
			}
		}
	}
	return m
}

// parseAddr converts the hex strings in /proc/net/tcp to readable IP:Port
func parseAddr(hexStr string, protocol string) (string, int) {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 {
		return "unknown", 0
	}

	port, _ := strconv.ParseInt(parts[1], 16, 32)
	ipHex, _ := hex.DecodeString(parts[0])

	// IPv4 is stored in little-endian in /proc/net/tcp
	if strings.HasSuffix(protocol, "6") {
		// Simplified IPv6 parsing using standard net.IP
		return net.IP(ipHex).String(), int(port)
	}

	// IPv4 Little-Endian to Big-Endian conversion
	if len(ipHex) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", ipHex[3], ipHex[2], ipHex[1], ipHex[0]), int(port)
	}

	return net.IP(ipHex).String(), int(port)
}

// isLocal checks if the address is a loopback or "any" interface
func isLocal(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "0.0.0.0" || addr == "::"
}

// getConnectionState maps the hex state code from /proc/net/tcp to a human-readable string
func getConnectionState(stateHex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
		"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
		"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[stateHex]; ok {
		return s
	}
	return "UNKNOWN"
}

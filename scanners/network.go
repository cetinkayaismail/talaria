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

// NetworkConnectionResult stores details about local network listeners
type NetworkConnectionResult struct {
	Protocol      string `json:"protocol"`
	LocalAddr     string `json:"local_addr"`
	LocalPort     int    `json:"local_port"`
	RemoteAddr    string `json:"remote_addr"`
	RemotePort    int    `json:"remote_port"`
	State         string `json:"state"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	IsDangerous   bool   `json:"is_dangerous"`
	RiskLevel     string `json:"risk_level"` // CRITICAL / HIGH / MEDIUM / INFO
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
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
			isFirstLine = false
			continue
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		localIP, localPort := parseAddr(fields[1], protocol)
		remoteIP, remotePort := parseAddr(fields[2], protocol)
		state := getConnectionState(fields[3])
		uid, _ := strconv.Atoi(fields[7])

		if state != "LISTEN" && state != "ESTABLISHED" {
			continue
		}

		// Skip outbound ephemeral client connections
		if state == "ESTABLISHED" && localPort >= 32768 {
			continue
		}

		// Skip common benign ports
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

		// 2. Port-to-Service map: used when process name is unknown
		//    Format: port → {likely service name, base risk level}
		//    Base risk: "CRITICAL", "HIGH", "MEDIUM", "LOW"
		type portInfo struct {
			name     string
			baseRisk string
		}
		portMap := map[int]portInfo{
			// LPE Gold Mine — always CRITICAL regardless of scope
			3306:  {"MySQL", "CRITICAL"},
			5432:  {"PostgreSQL", "CRITICAL"},
			6379:  {"Redis", "CRITICAL"},
			27017: {"MongoDB", "CRITICAL"},
			2375:  {"Docker API (unauthenticated)", "CRITICAL"},
			2376:  {"Docker API (TLS)", "CRITICAL"},
			11211: {"Memcached", "CRITICAL"},
			9000:  {"PHP-FPM", "CRITICAL"},
			// HIGH base risk
			2049: {"NFS", "HIGH"},
			21:   {"FTP", "HIGH"},
			23:   {"Telnet", "HIGH"},
			512:  {"rexec", "HIGH"},
			513:  {"rlogin", "HIGH"},
			514:  {"rsh", "HIGH"},
			// MEDIUM base risk
			631:  {"CUPS (printing)", "MEDIUM"},
			139:  {"Samba/NetBIOS", "MEDIUM"},
			445:  {"SMB/Samba", "MEDIUM"},
			111:  {"RPC/portmapper", "MEDIUM"},
			25:   {"SMTP", "MEDIUM"},
			110:  {"POP3", "MEDIUM"},
			143:  {"IMAP", "MEDIUM"},
			389:  {"LDAP", "MEDIUM"},
			8080: {"HTTP Proxy/App", "MEDIUM"},
			8443: {"HTTPS App", "MEDIUM"},
			9090: {"Web App", "MEDIUM"},
			5900: {"VNC", "MEDIUM"},
			3389: {"RDP", "MEDIUM"},
		}

		svc, known := portMap[localPort]
		if known && procName == "unknown" {
			procName = fmt.Sprintf("unknown (likely: %s)", svc.name)
		}

		// 3. Three-layer risk grading
		//    Layer 1 — Base risk from service type
		//    Layer 2 — Scope modifier: 0.0.0.0/:: bumps risk up one level
		//    Layer 3 — Context: localhost root listener is always at least HIGH

		baseRisk := "INFO"
		if known {
			baseRisk = svc.baseRisk
		} else if uid == 0 {
			baseRisk = "MEDIUM" // Unknown root service — default medium
		}

		// Layer 2: scope modifier
		isExposedAll := (localIP == "0.0.0.0" || localIP == "::") && state == "LISTEN"
		isLocalhost := (localIP == "127.0.0.1" || localIP == "::1") && state == "LISTEN"

		// Ephemeral high ports on 0.0.0.0 → skip (dynamic RPC/NFS helper ports)
		if isExposedAll && localPort >= 32768 {
			continue
		}

		// Non-root, non-known-service, not exposed → skip (noise)
		if !known && uid != 0 && !isExposedAll && !isLocalhost {
			continue
		}

		finalRisk := baseRisk
		reason := ""

		switch baseRisk {
		case "CRITICAL":
			if isLocalhost {
				reason = fmt.Sprintf("LPE Gold Mine: %s on localhost contains credentials or exploitable logic.", svc.name)
			} else {
				reason = fmt.Sprintf("EXPOSED LPE Gold Mine: %s exposed on all interfaces — credentials or exploitable logic accessible from network.", svc.name)
			}
		case "HIGH":
			if isExposedAll {
				finalRisk = "CRITICAL" // HIGH service on all interfaces → promote to CRITICAL
				reason = fmt.Sprintf("High-risk service (%s) exposed on all interfaces — direct attack surface from network.", svc.name)
			} else {
				reason = fmt.Sprintf("High-risk service (%s) listening locally.", svc.name)
			}
		case "MEDIUM":
			if isExposedAll && uid == 0 {
				finalRisk = "HIGH" // MEDIUM root service on all interfaces → promote to HIGH
				reason = fmt.Sprintf("Root-owned service (%s) exposed on all interfaces — misconfig may enable lateral movement.", svc.name)
			} else if isLocalhost && uid == 0 {
				reason = fmt.Sprintf("Root-owned %s on localhost — check for local exploitation or credential exposure.", svc.name)
			} else {
				reason = fmt.Sprintf("Service (%s) listening — review configuration.", svc.name)
			}
		default: // INFO / unknown
			if isExposedAll && uid == 0 {
				finalRisk = "MEDIUM"
				reason = "Unknown root service exposed on all interfaces — review manually."
			} else if isLocalhost && uid == 0 {
				finalRisk = "MEDIUM"
				reason = "Unknown root service on localhost — review manually."
			} else {
				// Not interesting enough — skip
				continue
			}
		}

		isDangerous := finalRisk == "CRITICAL" || finalRisk == "HIGH"
		remediation := ""
		if isDangerous || isExposedAll {
			remediation = fmt.Sprintf("Bind service on port %d to 127.0.0.1 or configure host firewall (iptables/nftables)", localPort)
		}

		results = append(results, NetworkConnectionResult{
			Protocol:      protocol,
			LocalAddr:     localIP,
			LocalPort:     localPort,
			RemoteAddr:    remoteIP,
			RemotePort:    remotePort,
			State:         state,
			PID:           0,
			ProcessName:   procName,
			IsDangerous:   isDangerous,
			RiskLevel:     finalRisk,
			Reason:        reason,
			Remediation:   remediation,
			ComplianceTag: "CIS-Linux-2.1.1 / NIST-SC-7",
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

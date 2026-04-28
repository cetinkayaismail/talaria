package scanners

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// NetworkConnectionResult stores details about local network listeners
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
}

// ScanNetworkConnections reads /proc/net to find internal services
func ScanNetworkConnections() ([]NetworkConnectionResult, error) {
	var results []NetworkConnectionResult

	// Scan TCP IPv4 and IPv6
	results = append(results, scanNetFile("/proc/net/tcp", "tcp")...)
	results = append(results, scanNetFile("/proc/net/tcp6", "tcp6")...)

	// Adding UDP might be useful for some services (e.g., DNS, SNMP)
	results = append(results, scanNetFile("/proc/net/udp", "udp")...)
	results = append(results, scanNetFile("/proc/net/udp6", "udp6")...)

	return results, nil
}

func scanNetFile(filePath string, protocol string) []NetworkConnectionResult {
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

		// DANGEROUS FILTERS:
		// - Root listening on non-standard ports on ANY interface (possible backdoor)
		// - Services on 0.0.0.0 that shouldn't be exposed
		isDangerous := false

		// Only care about root services or exposed services
		if state == "LISTEN" && uid == 0 && localPort > 1024 {
			// Root listening on high port = suspicious (could be backdoor)
			isDangerous = true
		} else if state == "LISTEN" && (isLocal(localIP) == false) {
			// Non-localhost listener (exposed to network)
			if localPort < 1024 && localPort != 80 && localPort != 443 {
				// Unusual exposed service
				isDangerous = true
			}
		}

		results = append(results, NetworkConnectionResult{
			Protocol:    protocol,
			LocalAddr:   localIP,
			LocalPort:   localPort,
			RemoteAddr:  remoteIP,
			RemotePort:  remotePort,
			State:       state,
			PID:         0, // Getting PID requires scanning /proc/[pid]/fd (omitted for speed)
			IsDangerous: isDangerous,
		})
	}
	return results
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

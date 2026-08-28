package scanners

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ServiceAuditResult holds findings for local service misconfigurations
type ServiceAuditResult struct {
	ServiceName   string `json:"service_name"`
	Port          int    `json:"port"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanLocalServices checks for locally running services with weak/no authentication
func ScanLocalServices() ([]ServiceAuditResult, error) {
	var results []ServiceAuditResult

	listeningPorts := getPassiveListeningPorts()

	// 1. MySQL Blank Password Check (only if port 3306 is listening)
	if listeningPorts[3306] {
		if res := checkMySQLBlankPassword(); res != nil {
			results = append(results, *res)
		}
	}

	// 2. Redis No Auth Check (only if port 6379 is listening)
	if listeningPorts[6379] {
		if res := checkRedisNoAuth(); res != nil {
			results = append(results, *res)
		}
	}

	// 3. Memcached Unauthenticated Check (port 11211)
	if listeningPorts[11211] {
		results = append(results, ServiceAuditResult{
			ServiceName:   "Memcached",
			Port:          11211,
			IsDangerous:   true,
			Reason:        "Memcached is listening locally — default installations require no authentication",
			ExploitHint:   "nc 127.0.0.1 11211 and run 'stats items' or 'stats cachedump' to dump session secrets",
			Remediation:   "Configure SASL authentication or bind memcached to unix socket",
			ComplianceTag: "CIS-Linux-2.1.1 / NIST-AC-3",
		})
	}

	return results, nil
}

func getPassiveListeningPorts() map[int]bool {
	ports := make(map[int]bool)
	for _, procNet := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(procNet)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		// Skip header
		if scanner.Scan() {
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 4 {
					state := fields[3]
					// 0A is TCP_LISTEN in procfs
					if state == "0A" {
						addrParts := strings.Split(fields[1], ":")
						if len(addrParts) == 2 {
							portHex := addrParts[1]
							if port, err := strconv.ParseInt(portHex, 16, 64); err == nil {
								ports[int(port)] = true
							}
						}
					}
				}
			}
		}
	}
	return ports
}

func checkMySQLBlankPassword() *ServiceAuditResult {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mysql", "-u", "root", "-e", "status")
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(strings.ToLower(string(output)), "uptime") {
		return &ServiceAuditResult{
			ServiceName:   "MySQL",
			Port:          3306,
			IsDangerous:   true,
			Reason:        "MySQL 'root' account has NO PASSWORD assigned. Accessible from localhost.",
			ExploitHint:   "Use UDF (User Defined Functions) to gain root shell: https://github.com/0xdeadbeef/mysql-udf-payloads",
			Remediation:   "Run 'mysql_secure_installation' and set strong root password",
			ComplianceTag: "CIS-Linux-2.1.1 / NIST-IA-5",
		}
	}
	return nil
}

func checkRedisNoAuth() *ServiceAuditResult {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "redis-cli", "INFO")
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(string(output), "redis_version") {
		return &ServiceAuditResult{
			ServiceName:   "Redis",
			Port:          6379,
			IsDangerous:   true,
			Reason:        "Redis instance requires NO AUTHENTICATION. Accessible from localhost.",
			ExploitHint:   "Overwrite root's .ssh/authorized_keys or add a root cronjob via Redis: redis-cli config set dir /root/.ssh",
			Remediation:   "Set 'requirepass <secret>' in /etc/redis/redis.conf",
			ComplianceTag: "CIS-Linux-2.1.1 / NIST-IA-5",
		}
	}
	return nil
}

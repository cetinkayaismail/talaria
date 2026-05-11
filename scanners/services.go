package scanners

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// ServiceAuditResult holds findings for local service misconfigurations
type ServiceAuditResult struct {
	ServiceName string `json:"service_name"`
	Port        int    `json:"port"`
	IsDangerous bool   `json:"is_dangerous"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint,omitempty"`
}

// ScanLocalServices checks for locally running services with weak/no authentication
func ScanLocalServices() ([]ServiceAuditResult, error) {
	var results []ServiceAuditResult

	// 1. MySQL Blank Password Check
	if res := checkMySQLBlankPassword(); res != nil {
		results = append(results, *res)
	}

	// 2. Redis No Auth Check
	if res := checkRedisNoAuth(); res != nil {
		results = append(results, *res)
	}

	return results, nil
}

func checkMySQLBlankPassword() *ServiceAuditResult {
	// Try to execute mysql status command without password
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mysql", "-u", "root", "-e", "status")
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(strings.ToLower(string(output)), "uptime") {
		return &ServiceAuditResult{
			ServiceName: "MySQL",
			Port:        3306,
			IsDangerous: true,
			Reason:      "MySQL 'root' account has NO PASSWORD assigned. Accessible from localhost.",
			ExploitHint: "Use UDF (User Defined Functions) to gain root shell: https://github.com/0xdeadbeef/mysql-udf-payloads",
		}
	}
	return nil
}

func checkRedisNoAuth() *ServiceAuditResult {
	// Try to execute redis-cli INFO command without password
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "redis-cli", "INFO")
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(string(output), "redis_version") {
		return &ServiceAuditResult{
			ServiceName: "Redis",
			Port:        6379,
			IsDangerous: true,
			Reason:      "Redis instance requires NO AUTHENTICATION. Accessible from localhost.",
			ExploitHint: "Overwrite root's .ssh/authorized_keys or add a root cronjob via Redis: redis-cli config set dir /root/.ssh",
		}
	}
	return nil
}

package scanners

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SubUIDResult represents an unprivileged namespace or subuid/subgid allocation finding.
type SubUIDResult struct {
	Type        string `json:"type"`
	TargetUser  string `json:"target_user"`
	StartID     int64  `json:"start_id"`
	Count       int64  `json:"count"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint"`
	IsDangerous bool   `json:"is_dangerous"`
}

// ScanSubUIDAuditor inspects /etc/subuid, /etc/subgid, and unprivileged user namespace sysctls.
func ScanSubUIDAuditor() ([]SubUIDResult, error) {
	var results []SubUIDResult

	// 1. Check unprivileged user namespace clone sysctl
	checkUserNamespaceSysctl(&results)

	// 2. Parse /etc/subuid
	parseSubIDFile("/etc/subuid", "subuid", &results)

	// 3. Parse /etc/subgid
	parseSubIDFile("/etc/subgid", "subgid", &results)

	return results, nil
}

func checkUserNamespaceSysctl(results *[]SubUIDResult) {
	paths := []string{
		"/proc/sys/kernel/unprivileged_userns_clone",
		"/proc/sys/user/max_user_namespaces",
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(data))
		if strings.HasSuffix(p, "unprivileged_userns_clone") {
			if val == "1" {
				*results = append(*results, SubUIDResult{
					Type:        "userns_unprivileged_enabled",
					TargetUser:  "all",
					RiskLevel:   "MEDIUM",
					Reason:      "Unprivileged user namespaces enabled (kernel.unprivileged_userns_clone=1) — expands kernel attack surface for namespace-based LPEs",
					ExploitHint: "sysctl -w kernel.unprivileged_userns_clone=0",
					IsDangerous: true,
				})
			}
		} else if strings.HasSuffix(p, "max_user_namespaces") {
			if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
				*results = append(*results, SubUIDResult{
					Type:        "userns_max_allowed",
					TargetUser:  "all",
					Count:       n,
					RiskLevel:   "INFO",
					Reason:      fmt.Sprintf("User namespaces allowed (max_user_namespaces=%d)", n),
					IsDangerous: false,
				})
			}
		}
	}
}

func parseSubIDFile(path string, idType string, results *[]SubUIDResult) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	userCtx := GetUserContext()
	currentUsername := ""
	if userCtx != nil {
		currentUsername = userCtx.Username
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			username := parts[0]
			startID, err1 := strconv.ParseInt(parts[1], 10, 64)
			count, err2 := strconv.ParseInt(parts[2], 10, 64)

			if err1 == nil && err2 == nil {
				isUserMatch := (currentUsername != "" && username == currentUsername)
				risk := "INFO"
				isDangerous := false
				reason := fmt.Sprintf("Allocated %s range %d-%d (%d IDs) in %s", idType, startID, startID+count-1, count, path)
				hint := ""

				if isUserMatch {
					risk = "MEDIUM"
					isDangerous = true
					reason = fmt.Sprintf("Current user '%s' possesses %s range allocation (%d IDs starting at %d) — enables rootless container mapping", username, idType, count, startID)
					hint = fmt.Sprintf("unshare -U -m -r  # Map UID 0 inside user namespace using subuid range in %s", path)
				}

				*results = append(*results, SubUIDResult{
					Type:        idType + "_allocation",
					TargetUser:  username,
					StartID:     startID,
					Count:       count,
					RiskLevel:   risk,
					Reason:      reason,
					ExploitHint: hint,
					IsDangerous: isDangerous,
				})
			}
		}
	}
}

package scanners

import (
	"fmt"
	"os"
	"syscall"
)

// CronDirResult represents a cron or timer drop-in directory permission drift finding.
type CronDirResult struct {
	Path        string `json:"path"`
	RiskLevel   string `json:"risk_level"`
	Reason      string `json:"reason"`
	ExploitHint string `json:"exploit_hint"`
	IsDangerous bool   `json:"is_dangerous"`
}

var targetCronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/crontab",
	"/var/spool/cron",
	"/var/spool/cron/crontabs",
	"/etc/systemd/system",
}

// ScanCronDirsAuditor audits system task drop-in directories for unprivileged write permissions.
func ScanCronDirsAuditor() ([]CronDirResult, error) {
	var results []CronDirResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	for _, dirPath := range targetCronDirs {
		info, err := os.Stat(dirPath)
		if err != nil {
			continue
		}

		if sys := info.Sys(); sys != nil {
			if stat, ok := sys.(*syscall.Stat_t); ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				mode := uint32(info.Mode().Perm())

				if userCtx.CanWrite(uid, gid, mode) {
					results = append(results, CronDirResult{
						Path:        dirPath,
						RiskLevel:   "CRITICAL",
						Reason:      fmt.Sprintf("Directory '%s' is writable by current user — unprivileged user can drop new crontab or systemd unit files to execute arbitrary commands as root", dirPath),
						ExploitHint: fmt.Sprintf("echo '* * * * * root /tmp/rootshell' > %s/evil_cron", dirPath),
						IsDangerous: true,
					})
				}
			}
		}
	}

	return results, nil
}

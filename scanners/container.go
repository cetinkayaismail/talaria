package scanners

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// ContainerEscapeResult holds findings about container environments and escape vectors
type ContainerEscapeResult struct {
	Vector        string `json:"vector"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanContainer detects if we are running inside a container (Docker/LXC/podman)
// and then checks for common escape vectors.
func ScanContainer() ([]ContainerEscapeResult, error) {
	var results []ContainerEscapeResult

	// 1. Detect container environment
	isContainer := false
	containerType := "unknown"

	// Check for .dockerenv (Docker always creates this)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isContainer = true
		containerType = "Docker"
	}

	// Check cgroup for docker/lxc/kubepods signatures (cgroup v1)
	if !isContainer {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			content := string(data)
			if strings.Contains(content, "docker") {
				isContainer = true
				containerType = "Docker (cgroup)"
			} else if strings.Contains(content, "lxc") {
				isContainer = true
				containerType = "LXC (cgroup)"
			} else if strings.Contains(content, "kubepods") {
				isContainer = true
				containerType = "Kubernetes Pod"
			} else if strings.TrimSpace(content) == "0::/" || strings.Contains(content, "0::/") {
				// cgroup v2: unified hierarchy shows "0::/" — cross-check with mountinfo (B5)
				if mountData, err := os.ReadFile("/proc/1/mountinfo"); err == nil {
					mc := string(mountData)
					if strings.Contains(mc, "overlay") || strings.Contains(mc, "docker") || strings.Contains(mc, "containerd") {
						isContainer = true
						containerType = "Container (cgroupv2 + overlay)"
					}
				}
			}
		}
	}

	// Check /proc/1/sched: PID 1 name reveals container vs host
	if !isContainer {
		if data, err := os.ReadFile("/proc/1/sched"); err == nil {
			firstLine := strings.SplitN(string(data), "\n", 2)[0]
			// On a host, this is usually "systemd (1, #threads: 1)"
			// In a container it might be "sh (1...)" or "bash (1...)"
			if !strings.Contains(firstLine, "systemd") && !strings.Contains(firstLine, "init") {
				isContainer = true
				containerType = "Container (sched heuristic: PID1=" + strings.Fields(firstLine)[0] + ")"
			}
		}
	}

	if !isContainer {
		// Not in a container — no escape vectors to report
		return results, nil
	}

	results = append(results, ContainerEscapeResult{
		Vector:      "Container Detected: " + containerType,
		IsDangerous: false,
		Reason:      "Running inside a container. Checking for escape vectors...",
	})

	// 2. Check for privileged container (--privileged)
	// In a privileged container, all capabilities are available
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			// CapEff: ffffffffffffffff means ALL capabilities (privileged)
			if strings.HasPrefix(line, "CapEff:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.ToLower(fields[1]) == "000001ffffffffff" ||
					strings.ToLower(fields[1]) == "ffffffffffffffff" {
					results = append(results, ContainerEscapeResult{
						Vector:        "Privileged Container",
						IsDangerous:   true,
						Reason:        "Container running with --privileged: all capabilities available. Mount host filesystem and chroot to escape.",
						Remediation:   "Disallow --privileged mode and drop unnecessary capabilities in container runtime spec",
						ComplianceTag: "CIS-Docker-5.4 / NIST-AC-6",
					})
				}
			}
		}
	}

	// 3. Check for Docker socket mounted inside the container
	dockerSockPaths := []string{"/var/run/docker.sock", "/run/docker.sock"}
	for _, dsp := range dockerSockPaths {
		if info, err := os.Stat(dsp); err == nil && (info.Mode()&os.ModeSocket) != 0 {
			results = append(results, ContainerEscapeResult{
				Vector:        "Docker Socket in Container",
				IsDangerous:   true,
				Reason:        dsp + " is mounted inside the container. Use docker run to spawn a privileged container and mount the host filesystem.",
				Remediation:   "Remove " + dsp + " mount from container volume configuration",
				ComplianceTag: "CIS-Docker-2.1 / NIST-AC-6",
			})
		}
	}

	// 4. Check for host PID namespace (--pid=host)
	// In host PID, we can see and signal all host processes
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		cmd := strings.ReplaceAll(string(data), "\x00", " ")
		// On host, PID 1 is systemd or init
		if strings.Contains(cmd, "systemd") || strings.Contains(cmd, "/sbin/init") {
			results = append(results, ContainerEscapeResult{
				Vector:        "Host PID Namespace",
				IsDangerous:   true,
				Reason:        "Container shares host PID namespace (--pid=host): can signal/ptrace host processes directly.",
				Remediation:   "Do not configure host PID namespace sharing (--pid=host) for unprivileged containers",
				ComplianceTag: "CIS-Docker-5.15 / NIST-SC-7",
			})
		}
	}

	// 5. Check for writable /proc/sysrq-trigger (requires host filesystem mount)
	if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
		f.Close()
		results = append(results, ContainerEscapeResult{
			Vector:        "Writable /proc/sysrq-trigger",
			IsDangerous:   true,
			Reason:        "Can write to sysrq-trigger: may indicate privileged access to host kernel interface.",
			Remediation:   "Mount /proc with read-only permissions inside container",
			ComplianceTag: "CIS-Docker-5.4 / NIST-SI-16",
		})
	}

	// 6. Check for sensitive host paths mounted inside container
	sensitiveMounts := []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh"}
	for _, p := range sensitiveMounts {
		if _, err := os.Stat(p); err == nil {
			results = append(results, ContainerEscapeResult{
				Vector:        "Sensitive Host Path Mounted: " + p,
				IsDangerous:   true,
				Reason:        "Host path " + p + " is accessible inside the container — may be a bind mount of the host filesystem.",
				Remediation:   "Remove bind mounts of sensitive host paths from container configuration",
				ComplianceTag: "CIS-Docker-5.4 / NIST-AC-6",
			})
		}
	}

	return results, nil
}

// ScanDBusPolicy checks /etc/dbus-1/system.d/ for permissive policy rules
// that allow unprivileged users to call methods on root-owned D-Bus services.
type DBusPolicyResult struct {
	ConfigFile    string `json:"config_file"`
	ServiceName   string `json:"service_name"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

func ScanDBusPolicy() ([]DBusPolicyResult, error) {
	var results []DBusPolicyResult

	configDirs := []string{"/etc/dbus-1/system.d", "/usr/share/dbus-1/system.d"}

	// Pre-fetch user info once outside the loop
	currUser, err := user.Current()
	if err != nil {
		return results, err
	}
	uid, _ := strconv.Atoi(currUser.Uid)
	gids := make(map[int]bool)
	for _, g := range func() []string { gs, _ := currUser.GroupIds(); return gs }() {
		id, _ := strconv.Atoi(g)
		gids[id] = true
	}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}

			filePath := dir + "/" + entry.Name()

			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			mode := stat.Mode
			fileWritable := false
			if uid == int(stat.Uid) && (mode&syscall.S_IWUSR != 0) {
				fileWritable = true
			} else if gids[int(stat.Gid)] && (mode&syscall.S_IWGRP != 0) {
				fileWritable = true
			} else if mode&syscall.S_IWOTH != 0 {
				fileWritable = true
			}

			if fileWritable {
				results = append(results, DBusPolicyResult{
					ConfigFile:    filePath,
					ServiceName:   strings.TrimSuffix(entry.Name(), ".conf"),
					IsDangerous:   true,
					Reason:        "D-Bus config file is writable: can modify policy to allow unprivileged access to privileged service methods",
					Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s", filePath, filePath),
					ComplianceTag: "CIS-Linux-5.3.5 / NIST-CM-6",
				})
			}
		}
	}

	return results, nil
}

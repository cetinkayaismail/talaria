package core

import (
	"fmt"
	"strings"
	"talaria/models"
)

type Node struct {
	ID   string
	Type string // "User", "File", "Group", "Goal", "Command"
}

type Edge struct {
	From        *Node
	To          *Node
	Description string // Action description
	Weight      int    // Risk/priority weight for path scoring
}

type Graph struct {
	Nodes map[string]*Node
	Edges map[string][]Edge
}

func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make(map[string][]Edge),
	}
}

func (g *Graph) AddNode(id string, nodeType string) *Node {
	if n, exists := g.Nodes[id]; exists {
		return n
	}
	n := &Node{ID: id, Type: nodeType}
	g.Nodes[id] = n
	return n
}

func (g *Graph) AddEdge(fromID, toID, desc string) {
	g.AddEdgeWeight(fromID, toID, desc, 1)
}

// AddEdgeWeight adds a weighted edge to the graph (#8).
// Automatically creates missing nodes with a generic type.
func (g *Graph) AddEdgeWeight(fromID, toID, desc string, weight int) {
	fromNode := g.AddNode(fromID, "auto")
	toNode := g.AddNode(toID, "auto")
	g.Edges[fromID] = append(g.Edges[fromID], Edge{From: fromNode, To: toNode, Description: desc, Weight: weight})
}

// BuildIntelligenceGraph creates a lightweight graph from interesting scan report findings
func BuildIntelligenceGraph(report *models.ScanReport) *Graph {
	g := NewGraph()

	currentUser := fmt.Sprintf("user:%s", report.TargetUser)
	g.AddNode(currentUser, "User")
	g.AddNode("goal:root", "Goal")
	g.AddNode("goal:sudo", "Goal")
	g.AddNode("goal:shadow", "Goal")
	g.AddNode("goal:docker_group", "Goal")

	// 1. Map Writable Files
	for _, w := range report.Writeable {
		fileID := fmt.Sprintf("file:%s", w.Path)
		g.AddNode(fileID, "File")
		weight := 5
		if w.RiskLevel == "CRITICAL" {
			weight = 10
		}
		g.AddEdgeWeight(currentUser, fileID, "Can write to", weight)
	}

	// 2. Map CronJobs
	for _, cron := range report.CronJobs {
		// Identify user goals from cronjob owners
		targetUser := cron.Owner
		if targetUser == "" || targetUser == report.TargetUser {
			continue
		}

		userGoal := fmt.Sprintf("goal:user:%s", targetUser)
		if targetUser == "root" || targetUser == "0" {
			userGoal = "goal:root"
		}

		for _, w := range report.Writeable {
			if resolveCommandPath(cron.Command, w.Path) {
				fileID := fmt.Sprintf("file:%s", w.Path)
				g.AddNode(fileID, "File")
				g.AddEdgeWeight(fileID, userGoal, fmt.Sprintf("Executed by %s CronJob: %s", targetUser, cron.Command), 10)
			}
		}
	}

	// 3. Map Sudo Privileges
	for _, sudo := range report.SudoPrivileges {
		if sudo.NoPassword {
			targetUser := sudo.RunAs
			userGoal := fmt.Sprintf("goal:user:%s", targetUser)
			if strings.Contains(targetUser, "root") || targetUser == "0" {
				userGoal = "goal:root"
			}

			if strings.Contains(sudo.Command, "ALL") {
				if targetUser != report.TargetUser {
					g.AddEdgeWeight(currentUser, userGoal, fmt.Sprintf("NOPASSWD sudo ALL as %s", targetUser), 9)
				}
			} else {
				cmdID := fmt.Sprintf("cmd:%s", sudo.Command)
				g.AddNode(cmdID, "Command")
				if targetUser != report.TargetUser {
					g.AddEdgeWeight(currentUser, cmdID, fmt.Sprintf("NOPASSWD sudo as %s", targetUser), 7)
				}
				for _, w := range report.Writeable {
					if resolveCommandPath(sudo.Command, w.Path) {
						fileID := fmt.Sprintf("file:%s", w.Path)
						g.AddEdgeWeight(cmdID, fileID, "Executes writable file", 8)
						g.AddEdgeWeight(fileID, userGoal, fmt.Sprintf("Results in %s execution", targetUser), 10)
					}
				}
			}
		}
	}

	// 4. Map Groups (e.g., Docker, LXD)
	for _, grp := range report.Groups {
		grpID := fmt.Sprintf("group:%s", grp.GroupName)
		g.AddNode(grpID, "Group")
		g.AddEdgeWeight(currentUser, grpID, "Member of group", 3)

		switch strings.ToLower(grp.GroupName) {
		case "docker":
			g.AddEdgeWeight(grpID, "goal:root", "Docker group provides trivial root access", 10)
		case "lxd":
			g.AddEdgeWeight(grpID, "goal:root", "LXD group provides trivial root access", 10)
		case "shadow":
			g.AddEdgeWeight(grpID, "goal:shadow", "Shadow group allows cracking passwords", 7)
		case "disk":
			g.AddEdgeWeight(grpID, "goal:root", "Disk group allows raw disk read/write", 8)
		}
	}

	// 5. Map Sockets (Docker socket)
	for _, sock := range report.Sockets {
		if strings.Contains(sock.Service, "docker") && sock.IsDangerous {
			sockID := "sock:docker.sock"
			g.AddNode(sockID, "File")
			g.AddEdgeWeight(currentUser, sockID, "Can access Docker socket", 9)
			g.AddEdgeWeight(sockID, "goal:root", "Docker socket provides trivial root access", 10)
		}
	}

	// 6. Map PATH hijack + SUID cross-chain (#1)
	for _, ph := range report.PATHHijack {
		if ph.IsDangerous && ph.IsWriteable {
			pathID := fmt.Sprintf("path:%s", ph.Directory)
			g.AddNode(pathID, "File")
			g.AddEdgeWeight(currentUser, pathID, "Writable PATH entry", 6)
			for _, suid := range report.SUID {
				if suid.IsDangerous && !strings.HasPrefix(suid.Path, "/snap") {
					suidID := fmt.Sprintf("suid:%s", suid.Path)
					g.AddNode(suidID, "File")
					g.AddEdgeWeight(pathID, suidID, "Writable PATH can hijack SUID script", 9)
					g.AddEdgeWeight(suidID, "goal:root", "SUID binary provides root", 10)
				}
			}
		}
	}

	// 7. Map writable .service files to root goal (#3)
	for _, w := range report.Writeable {
		if strings.Contains(w.Type, "Systemd Service") || strings.Contains(w.Type, "Systemd Generator") {
			fileID := fmt.Sprintf("file:%s", w.Path)
			g.AddEdgeWeight(fileID, "goal:root", "Writable systemd unit — root execution on restart", 10)
		}
	}

	// 8. Map tmux/screen session hijack to user goals (#4)
	for _, sh := range report.SessionHijack {
		if sh.IsDangerous {
			targetUser := sh.TargetUser
			if targetUser == report.TargetUser {
				continue
			}

			userGoal := fmt.Sprintf("goal:user:%s", targetUser)
			if strings.Contains(targetUser, "root") || targetUser == "0" {
				userGoal = "goal:root"
			}

			sessionID := fmt.Sprintf("session:%s", sh.Path)
			g.AddNode(sessionID, "File")
			g.AddEdgeWeight(currentUser, sessionID, "Can hijack terminal session", 8)
			g.AddEdgeWeight(sessionID, userGoal, fmt.Sprintf("%s session hijack", targetUser), 10)
		}
	}

	// 9. Map SSH Keys to user goals
	for _, key := range report.SSHKeys {
		if key.IsDangerous && key.TargetUser != report.TargetUser {
			targetUser := key.TargetUser
			userGoal := fmt.Sprintf("goal:user:%s", targetUser)
			if strings.Contains(targetUser, "root") || targetUser == "0" {
				userGoal = "goal:root"
			}

			keyID := fmt.Sprintf("file:%s", key.Path)
			g.AddNode(keyID, "File")
			g.AddEdgeWeight(currentUser, keyID, fmt.Sprintf("Can access %s for %s", key.Type, targetUser), 8)
			g.AddEdgeWeight(keyID, userGoal, fmt.Sprintf("SSH access as %s", targetUser), 10)
		}
	}

	// 10. Map File Permissions
	for _, fp := range report.FilePermissions {
		if !fp.IsDangerous {
			continue
		}
		fileID := fmt.Sprintf("file:%s", fp.Path)
		g.AddNode(fileID, "File")
		if fp.Path == "/etc/passwd" && (fp.IsWorldWritable || fp.IsGroupWritable) {
			g.AddEdgeWeight(currentUser, fileID, "Can write to /etc/passwd", 10)
			g.AddEdgeWeight(fileID, "goal:root", "Writable passwd allows adding privileged user", 10)
		} else if fp.Path == "/etc/shadow" {
			if fp.IsWorldWritable || fp.IsGroupWritable {
				g.AddEdgeWeight(currentUser, fileID, "Can write to /etc/shadow", 10)
				g.AddEdgeWeight(fileID, "goal:root", "Writable shadow allows changing root password", 10)
			} else if fp.IsWorldReadable || fp.Permissions == "readable" {
				g.AddEdgeWeight(currentUser, fileID, "Can read /etc/shadow", 8)
				g.AddEdgeWeight(fileID, "goal:shadow", "Readable shadow allows cracking password hashes", 10)
			}
		} else if fp.Path == "/etc/sudoers" && (fp.IsWorldWritable || fp.IsGroupWritable) {
			g.AddEdgeWeight(currentUser, fileID, "Can write to /etc/sudoers", 10)
			g.AddEdgeWeight(fileID, "goal:root", "Writable sudoers allows arbitrary NOPASSWD privileges", 10)
		} else if strings.HasPrefix(fp.Path, "/etc/sudoers.d/") && (fp.IsWorldWritable || fp.IsGroupWritable) {
			g.AddEdgeWeight(currentUser, fileID, fmt.Sprintf("Can write to sudoers drop-in %s", fp.Path), 10)
			g.AddEdgeWeight(fileID, "goal:root", "Writable sudoers drop-in allows adding root privileges", 10)
		} else if strings.HasPrefix(fp.Path, "/etc/ld.so.conf") && (fp.IsWorldWritable || fp.IsGroupWritable) {
			g.AddEdgeWeight(currentUser, fileID, fmt.Sprintf("Can write to library loader config %s", fp.Path), 9)
			g.AddEdgeWeight(fileID, "goal:root", "Writable ld.so.conf allows library injection", 10)
		} else if strings.HasPrefix(fp.Path, "/etc/logrotate.d/") && (fp.IsWorldWritable || fp.IsGroupWritable) {
			g.AddEdgeWeight(currentUser, fileID, fmt.Sprintf("Can write to logrotate config %s", fp.Path), 8)
			g.AddEdgeWeight(fileID, "goal:root", "Writable logrotate allows privilege escalation via postrotate commands", 9)
		}
	}

	// 11. Map Capabilities
	for _, capResult := range report.Capabilities {
		if !capResult.IsDangerous {
			continue
		}
		capID := fmt.Sprintf("file:%s", capResult.Path)
		g.AddNode(capID, "File")
		capsLower := strings.ToLower(capResult.Capabilities)
		if strings.Contains(capsLower, "cap_setuid") || strings.Contains(capsLower, "cap_sys_admin") || strings.Contains(capsLower, "cap_dac_override") {
			g.AddEdgeWeight(currentUser, capID, fmt.Sprintf("Can execute capability binary %s", capResult.Path), 9)
			g.AddEdgeWeight(capID, "goal:root", fmt.Sprintf("Binary has %s", capResult.Capabilities), 10)
		} else if strings.Contains(capsLower, "cap_dac_read_search") {
			g.AddEdgeWeight(currentUser, capID, fmt.Sprintf("Can execute capability binary %s", capResult.Path), 8)
			g.AddEdgeWeight(capID, "goal:shadow", fmt.Sprintf("Binary has %s (bypass file read checks)", capResult.Capabilities), 9)
		}
	}

	// 12. Map NFS Exports with no_root_squash
	for _, nfs := range report.NFSExports {
		if nfs.IsDangerous && nfs.IsWritable && nfs.HasNoRootSquash {
			nfsID := fmt.Sprintf("file:%s", nfs.Path)
			g.AddNode(nfsID, "File")
			g.AddEdgeWeight(currentUser, nfsID, fmt.Sprintf("Can access writable NFS export %s", nfs.Path), 9)
			g.AddEdgeWeight(nfsID, "goal:root", "NFS export has no_root_squash (upload SUID binary)", 10)
		}
	}

	// 13. Map Polkit Rules
	for _, pk := range report.PolkitRules {
		if !pk.IsDangerous {
			continue
		}
		ruleID := fmt.Sprintf("file:%s", pk.FilePath)
		g.AddNode(ruleID, "File")
		g.AddEdgeWeight(currentUser, ruleID, fmt.Sprintf("Subject to custom Polkit rule in %s", pk.FilePath), 9)
		g.AddEdgeWeight(ruleID, "goal:root", fmt.Sprintf("Rule grants passwordless authorization for %s", pk.Action), 10)
	}

	// 14. Map PAM Misconfigurations & Writable Modules
	for _, pam := range report.PAMResults {
		if !pam.IsDangerous {
			continue
		}
		pamID := fmt.Sprintf("file:%s", pam.Path)
		g.AddNode(pamID, "File")
		g.AddEdgeWeight(currentUser, pamID, fmt.Sprintf("Can access writable PAM asset %s (%s)", pam.Path, pam.Type), 9)
		g.AddEdgeWeight(pamID, "goal:root", fmt.Sprintf("PAM %s permits authentication bypass / root code execution", pam.Type), 10)
	}

	// 15. Map Systemd EnvironmentFile Results
	for _, ef := range report.EnvFileResults {
		if !ef.IsWritable {
			continue
		}
		envID := fmt.Sprintf("file:%s", ef.EnvFilePath)
		g.AddNode(envID, "File")
		g.AddEdgeWeight(currentUser, envID, fmt.Sprintf("Can write to Systemd EnvironmentFile %s", ef.EnvFilePath), 9)
		g.AddEdgeWeight(envID, "goal:root", fmt.Sprintf("Service %s executes %s payload as root on restart", ef.ServiceName, ef.InjectionType), 10)
	}

	// 16. Map Kernel Sysctl Hardening Gaps
	for _, sys := range report.SysctlResults {
		if !sys.IsDangerous {
			continue
		}
		sysID := fmt.Sprintf("sysctl:%s", sys.Key)
		g.AddNode(sysID, "File")
		g.AddEdgeWeight(currentUser, sysID, fmt.Sprintf("Unprotected sysctl %s = %s", sys.Key, sys.CurrentValue), 7)
		g.AddEdgeWeight(sysID, "goal:root", sys.Reason, 8)
	}

	// 17. Map Systemd Unit Overrides
	for _, ov := range report.SystemdOverrides {
		if !ov.IsDangerous {
			continue
		}
		ovID := fmt.Sprintf("file:%s", ov.Path)
		g.AddNode(ovID, "File")
		g.AddEdgeWeight(currentUser, ovID, fmt.Sprintf("Can access Systemd override %s (%s)", ov.Path, ov.Type), 9)
		g.AddEdgeWeight(ovID, "goal:root", fmt.Sprintf("Systemd override for service %s grants root code execution", ov.ServiceName), 10)
	}

	// 18. Map SubUID / Unprivileged User Namespaces
	for _, sub := range report.SubUIDResults {
		if !sub.IsDangerous {
			continue
		}
		subID := fmt.Sprintf("subuid:%s", sub.Type)
		g.AddNode(subID, "File")
		g.AddEdgeWeight(currentUser, subID, fmt.Sprintf("Has %s (%s)", sub.Type, sub.TargetUser), 6)
		g.AddEdgeWeight(subID, "goal:root", "User namespace creation enables unprivileged container root mapping", 7)
	}

	// 19. Map Shared Memory & Temp Mount Flags
	for _, m := range report.MountResults {
		if !m.IsDangerous {
			continue
		}
		mntID := fmt.Sprintf("mount:%s", m.MountPoint)
		g.AddNode(mntID, "File")
		g.AddEdgeWeight(currentUser, mntID, fmt.Sprintf("Can write to executable temp mount %s (missing %s)", m.MountPoint, m.MissingFlag), 6)
		g.AddEdgeWeight(mntID, "goal:root", fmt.Sprintf("Executable mount %s permits binary payload execution", m.MountPoint), 7)
	}

	// 20. Map Dynamic ELF RPATH / RUNPATH Vectors
	for _, r := range report.ELFRPathResults {
		if !r.IsDangerous {
			continue
		}
		elfID := fmt.Sprintf("file:%s", r.Path)
		g.AddNode(elfID, "File")
		g.AddEdgeWeight(currentUser, elfID, fmt.Sprintf("Can hijack SUID binary %s via %s %s", r.Path, r.TagType, r.Value), 9)
		g.AddEdgeWeight(elfID, "goal:root", "Shared library hijacking on SUID binary yields root", 10)
	}

	// 21. Map Udev Event Rules & Execution Targets
	for _, u := range report.UdevResults {
		if !u.IsDangerous {
			continue
		}
		udevID := fmt.Sprintf("file:%s", u.Path)
		g.AddNode(udevID, "File")
		g.AddEdgeWeight(currentUser, udevID, fmt.Sprintf("Can write to udev rule / target %s (%s)", u.Path, u.Directive), 10)
		g.AddEdgeWeight(udevID, "goal:root", "Udev event rule execution grants root code execution on device events", 10)
	}

	// 22. Map Cron & Timer Directory Permission Drift
	for _, cd := range report.CronDirResults {
		if !cd.IsDangerous {
			continue
		}
		cdID := fmt.Sprintf("file:%s", cd.Path)
		g.AddNode(cdID, "File")
		g.AddEdgeWeight(currentUser, cdID, fmt.Sprintf("Can write to system task directory %s", cd.Path), 10)
		g.AddEdgeWeight(cdID, "goal:root", "Cron/task directory writability permits arbitrary root payload creation", 10)
	}

	// 23. Map Exposed Process Environment Secrets
	for _, pe := range report.ProcEnvResults {
		if !pe.IsDangerous {
			continue
		}
		peID := fmt.Sprintf("procenv:%d:%s", pe.PID, pe.Key)
		g.AddNode(peID, "Credential")
		g.AddEdgeWeight(currentUser, peID, fmt.Sprintf("Exposed environment secret %s in process %s (PID %d)", pe.Key, pe.ProcessName, pe.PID), 8)
		g.AddEdgeWeight(peID, "goal:root", fmt.Sprintf("Plaintext secret %s in /proc/%d/environ allows authentication / escalation", pe.Key, pe.PID), 9)
	}

	// 24. Map Package Manager Hooks & Repository Configurations
	for _, pkg := range report.Packages {
		if !pkg.IsDangerous {
			continue
		}
		pkgID := fmt.Sprintf("file:%s", pkg.Path)
		if pkg.Path == "" {
			pkgID = fmt.Sprintf("pkg:%s", pkg.Name)
		}
		g.AddNode(pkgID, "File")
		weight := 7
		if pkg.IsHookDir {
			weight = 10
		}
		g.AddEdgeWeight(currentUser, pkgID, fmt.Sprintf("Can write to package manager %s configuration/hook (%s)", pkg.Name, pkg.Path), weight)
		g.AddEdgeWeight(pkgID, "goal:root", fmt.Sprintf("Package manager %s executes arbitrary root commands on package events", pkg.Name), weight)
	}

	// 25. Map Dynamic Linker & NSS Configuration Flaws
	for _, r := range report.LDNSSResults {
		if !r.IsDangerous {
			continue
		}
		ldID := fmt.Sprintf("file:%s", r.Path)
		g.AddNode(ldID, "File")
		g.AddEdgeWeight(currentUser, ldID, fmt.Sprintf("Can write to dynamic linker / NSS path %s", r.Path), 10)
		g.AddEdgeWeight(ldID, "goal:root", "Shared library injection into dynamic linker yields root execution", 10)
	}

	// 26. Map Modprobe Kernel Module Execution Hooks
	for _, m := range report.ModprobeResults {
		if !m.IsDangerous {
			continue
		}
		modID := fmt.Sprintf("file:%s", m.Path)
		g.AddNode(modID, "File")
		g.AddEdgeWeight(currentUser, modID, fmt.Sprintf("Can write to modprobe configuration / target %s", m.Path), 10)
		g.AddEdgeWeight(modID, "goal:root", "Kernel module loading executes arbitrary root commands", 10)
	}

	// 27. Map Cloud & Kubernetes Credential Harvester
	for _, cm := range report.CloudMetaResults {
		if !cm.IsDangerous {
			continue
		}
		cmID := fmt.Sprintf("cloud:%s", cm.Provider)
		if cm.Path != "" {
			cmID = fmt.Sprintf("file:%s", cm.Path)
		}
		g.AddNode(cmID, "Credential")
		g.AddEdgeWeight(currentUser, cmID, fmt.Sprintf("Exposed %s credential token / metadata endpoint", cm.Provider), 9)
		g.AddEdgeWeight(cmID, "goal:root", fmt.Sprintf("%s credential allows cluster/infrastructure privilege takeover", cm.Provider), 9)
	}

	// 28. Map VirtualEnv & Wrapper Executables
	for _, vw := range report.VenvWrapResults {
		if !vw.IsDangerous {
			continue
		}
		vwID := fmt.Sprintf("file:%s", vw.Path)
		g.AddNode(vwID, "File")
		g.AddEdgeWeight(currentUser, vwID, fmt.Sprintf("Can write to %s %s", vw.TargetType, vw.Path), 9)
		g.AddEdgeWeight(vwID, "goal:root", "Execution of poisoned package or wrapper by root grants root", 10)
	}

	return g
}

// FindBestPath finds the highest-weighted path from start to target, not just shortest
func (g *Graph) FindBestPath(startID, targetID string, maxDepth int) []Edge {
	if g.Nodes[startID] == nil || g.Nodes[targetID] == nil {
		return nil
	}

	type scoredPath struct {
		path  []Edge
		score int
	}

	var best *scoredPath
	var currentPath []Edge
	visited := make(map[string]bool)

	var dfs func(curr string, depth int, score int)
	dfs = func(curr string, depth int, score int) {
		if curr == targetID {
			pathCopy := make([]Edge, len(currentPath))
			copy(pathCopy, currentPath)
			if best == nil || score > best.score {
				best = &scoredPath{path: pathCopy, score: score}
			}
			return
		}
		if depth >= maxDepth {
			return
		}

		visited[curr] = true
		for _, edge := range g.Edges[curr] {
			if !visited[edge.To.ID] {
				currentPath = append(currentPath, edge)
				dfs(edge.To.ID, depth+1, score+edge.Weight)
				currentPath = currentPath[:len(currentPath)-1]
			}
		}
		visited[curr] = false
	}

	dfs(startID, 0, 0)

	if best != nil {
		return best.path
	}
	return nil
}

// FindPaths finds all paths from startID to targetID up to maxDepth (backward compat)
func (g *Graph) FindPaths(startID, targetID string, maxDepth int) [][]Edge {
	if g.Nodes[startID] == nil || g.Nodes[targetID] == nil {
		return nil
	}

	var allPaths [][]Edge
	var currentPath []Edge
	visited := make(map[string]bool)

	var dfs func(curr string, depth int)
	dfs = func(curr string, depth int) {
		if curr == targetID {
			pathCopy := make([]Edge, len(currentPath))
			copy(pathCopy, currentPath)
			allPaths = append(allPaths, pathCopy)
			return
		}
		if depth >= maxDepth {
			return
		}

		visited[curr] = true
		for _, edge := range g.Edges[curr] {
			if !visited[edge.To.ID] {
				currentPath = append(currentPath, edge)
				dfs(edge.To.ID, depth+1)
				currentPath = currentPath[:len(currentPath)-1]
			}
		}
		visited[curr] = false
	}

	dfs(startID, 0)
	return allPaths
}

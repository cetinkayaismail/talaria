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

	return g
}

// FindBestPath finds the highest-weighted path from start to target, not just shortest
func (g *Graph) FindBestPath(startID, targetID string, maxDepth int) []Edge {
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
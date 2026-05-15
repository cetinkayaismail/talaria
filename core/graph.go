package core

import (
	"fmt"
	"strings"
	"Talaria/models"
)

type Node struct {
	ID   string
	Type string // "User", "File", "Group", "Goal", "Command"
}

type Edge struct {
	From        *Node
	To          *Node
	Description string // Action description
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
	fromNode := g.Nodes[fromID]
	toNode := g.Nodes[toID]
	if fromNode == nil || toNode == nil {
		return
	}
	g.Edges[fromID] = append(g.Edges[fromID], Edge{From: fromNode, To: toNode, Description: desc})
}

// BuildIntelligenceGraph creates a lightweight graph from interesting scan report findings
func BuildIntelligenceGraph(report *models.ScanReport) *Graph {
	g := NewGraph()

	currentUser := fmt.Sprintf("user:%s", report.TargetUser)
	g.AddNode(currentUser, "User")
	g.AddNode("goal:root", "Goal")

	// 1. Map Writable Files
	for _, w := range report.Writeable {
		fileID := fmt.Sprintf("file:%s", w.Path)
		g.AddNode(fileID, "File")
		g.AddEdge(currentUser, fileID, "Can write to")
	}

	// 2. Map CronJobs
	for _, cron := range report.CronJobs {
		if cron.IsRootJob {
			// Find if this cron executes any writable file
			for _, w := range report.Writeable {
				if resolveCommandPath(cron.Command, w.Path) {
					fileID := fmt.Sprintf("file:%s", w.Path)
					// If the file exists in the graph, it executes as root
					g.AddNode(fileID, "File")
					g.AddEdge(fileID, "goal:root", fmt.Sprintf("Executed by root CronJob: %s", cron.Command))
				}
			}
		}
	}

	// 3. Map Sudo Privileges
	for _, sudo := range report.SudoPrivileges {
		if sudo.NoPassword {
			if strings.Contains(sudo.Command, "ALL") {
				g.AddEdge(currentUser, "goal:root", "NOPASSWD sudo ALL")
			} else {
				cmdID := fmt.Sprintf("cmd:%s", sudo.Command)
				g.AddNode(cmdID, "Command")
				g.AddEdge(currentUser, cmdID, "NOPASSWD sudo")
				// Does this command target a writable file?
				for _, w := range report.Writeable {
					if resolveCommandPath(sudo.Command, w.Path) {
						fileID := fmt.Sprintf("file:%s", w.Path)
						g.AddEdge(cmdID, fileID, "Executes writable file")
						g.AddEdge(fileID, "goal:root", "Results in root execution")
					}
				}
			}
		}
	}

	// 4. Map Groups (e.g., Docker, LXD)
	for _, grp := range report.Groups {
		grpID := fmt.Sprintf("group:%s", grp.GroupName)
		g.AddNode(grpID, "Group")
		g.AddEdge(currentUser, grpID, "Member of group")

		if strings.EqualFold(grp.GroupName, "docker") {
			g.AddEdge(grpID, "goal:root", "Docker group provides trivial root access")
		} else if strings.EqualFold(grp.GroupName, "lxd") {
			g.AddEdge(grpID, "goal:root", "LXD group provides trivial root access")
		} else if strings.EqualFold(grp.GroupName, "shadow") {
			g.AddEdge(grpID, "goal:root", "Shadow group allows cracking passwords")
		}
	}

	// 5. Map Sockets (Docker socket)
	for _, sock := range report.Sockets {
		if strings.Contains(sock.Service, "docker") && sock.IsDangerous {
			sockID := "sock:docker.sock"
			g.AddNode(sockID, "File")
			// If socket is accessible by current user or a group
			// We simplify here: if it's marked dangerous, we assume current user can access it
			g.AddEdge(currentUser, sockID, "Can access Docker socket")
			g.AddEdge(sockID, "goal:root", "Docker socket provides trivial root access")
		}
	}

	return g
}

func (g *Graph) FindPaths(startID, targetID string, maxDepth int) [][]Edge {
	var allPaths [][]Edge
	var currentPath []Edge
	visited := make(map[string]bool)

	var dfs func(curr string, depth int)
	dfs = func(curr string, depth int) {
		if curr == targetID {
			// Found a path, copy and save it
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
				currentPath = currentPath[:len(currentPath)-1] // backtrack
			}
		}
		visited[curr] = false // backtrack
	}

	dfs(startID, 0)
	return allPaths
}

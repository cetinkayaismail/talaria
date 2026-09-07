package core

import (
	"talaria/models"
	"talaria/scanners"
	"testing"
)

func TestGraphCreationAndEdges(t *testing.T) {
	g := NewGraph()

	n1 := g.AddNode("user:audit", "User")
	n2 := g.AddNode("goal:root", "Goal")

	if n1.ID != "user:audit" || n1.Type != "User" {
		t.Fatalf("Unexpected node n1: %+v", n1)
	}
	if n2.ID != "goal:root" || n2.Type != "Goal" {
		t.Fatalf("Unexpected node n2: %+v", n2)
	}

	g.AddEdgeWeight("user:audit", "goal:root", "Direct privilege escalation", 10)

	edges, ok := g.Edges["user:audit"]
	if !ok || len(edges) != 1 {
		t.Fatalf("Expected 1 edge from user:audit, got %d", len(edges))
	}

	if edges[0].Weight != 10 {
		t.Fatalf("Expected weight 10, got %d", edges[0].Weight)
	}
	if edges[0].Description != "Direct privilege escalation" {
		t.Fatalf("Unexpected description: %s", edges[0].Description)
	}
}

func TestBuildIntelligenceGraph(t *testing.T) {
	report := &models.ScanReport{
		TargetUser: "appuser",
		Groups: []scanners.GroupResult{
			{
				GroupName:   "docker",
				IsDangerous: true,
			},
		},
		Sockets: []scanners.SocketResult{
			{
				Path:        "/var/run/docker.sock",
				Service:     "docker",
				IsDangerous: true,
			},
		},
	}

	g := BuildIntelligenceGraph(report)

	if _, exists := g.Nodes["user:appuser"]; !exists {
		t.Fatal("Expected node user:appuser to exist")
	}
	if _, exists := g.Nodes["goal:root"]; !exists {
		t.Fatal("Expected node goal:root to exist")
	}
	if _, exists := g.Nodes["group:docker"]; !exists {
		t.Fatal("Expected node group:docker to exist")
	}

	// Verify edge from group:docker to goal:root
	edges := g.Edges["group:docker"]
	found := false
	for _, e := range edges {
		if e.To.ID == "goal:root" {
			found = true
			if e.Weight != 10 {
				t.Fatalf("Expected edge weight 10, got %d", e.Weight)
			}
		}
	}
	if !found {
		t.Fatal("Expected edge from group:docker to goal:root")
	}
}

func TestFindPathsAndBestSinglePass(t *testing.T) {
	g := NewGraph()
	g.AddNode("user:test", "User")
	g.AddNode("node:stepA", "File")
	g.AddNode("node:stepB", "File")
	g.AddNode("goal:root", "Goal")

	// Path 1: test -> stepA -> root (weight: 3 + 4 = 7)
	g.AddEdgeWeight("user:test", "node:stepA", "stepA", 3)
	g.AddEdgeWeight("node:stepA", "goal:root", "reach root via A", 4)

	// Path 2: test -> stepB -> root (weight: 2 + 10 = 12) (best path)
	g.AddEdgeWeight("user:test", "node:stepB", "stepB", 2)
	g.AddEdgeWeight("node:stepB", "goal:root", "reach root via B", 10)

	allPaths, bestPath := g.FindPathsAndBest("user:test", "goal:root", 5)

	if len(allPaths) != 2 {
		t.Fatalf("Expected 2 paths, got %d", len(allPaths))
	}

	if len(bestPath) != 2 {
		t.Fatalf("Expected best path of length 2, got %d", len(bestPath))
	}

	if bestPath[0].To.ID != "node:stepB" || bestPath[1].To.ID != "goal:root" {
		t.Fatalf("Expected best path through node:stepB, got %+v", bestPath)
	}

	// Verify FindPaths wrapper matches allPaths
	pathsOnly := g.FindPaths("user:test", "goal:root", 5)
	if len(pathsOnly) != 2 {
		t.Fatalf("Expected FindPaths to return 2 paths, got %d", len(pathsOnly))
	}

	// Verify FindBestPath wrapper matches bestPath
	bestOnly := g.FindBestPath("user:test", "goal:root", 5)
	if len(bestOnly) != 2 || bestOnly[0].To.ID != "node:stepB" {
		t.Fatalf("Expected FindBestPath to return path through stepB, got %+v", bestOnly)
	}
}


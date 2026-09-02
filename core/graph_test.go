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

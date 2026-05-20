package scanners

import (
	"testing"
)

func TestParsePolkitContent(t *testing.T) {
	// A mock rules file with comments, standard safe rules, and a highly vulnerable rule
	mockContent := `
	// This is a single-line comment that should be stripped
	/* Multi-line comments
	   polkit.addRule(function(action, subject) {
		   return polkit.Result.YES; // Commented out! Should NOT be flagged.
	   });
	*/

	// Safe Rule 1: Allows wheel group to perform any action (standard administration)
	polkit.addRule(function(action, subject) {
		if (subject.isInGroup("wheel")) {
			return polkit.Result.YES;
		}
	});

	// Safe Rule 2: Allows sudo group to manage systemd units
	polkit.addRule(function(action, subject) {
		if (action.id.indexOf("org.freedesktop.systemd1.") == 0 &&
			subject.isInGroup("sudo")) {
			return polkit.Result.YES;
		}
	});

	// Safe Rule 3: Allows root user to manage services
	polkit.addRule(function(action, subject) {
		if (subject.user == "root") {
			return polkit.Result.YES;
		}
	});

	// Vulnerable Rule 1: Allows users group to manage disks without password! (VULNERABLE)
	polkit.addRule(function(action, subject) {
		if (action.id == "org.freedesktop.udisks2.filesystem-mount" &&
			subject.isInGroup("users")) {
			return polkit.Result.YES;
		}
	});

	// Vulnerable Rule 2: Grant unconditional YES to any user for virtualization! (CRITICAL VULNERABILITY)
	polkit.addRule(function(action, subject) {
		if (action.id == "org.libvirt.api.connect.getattr") {
			return polkit.Result.YES;
		}
	});
	`

	results := parsePolkitContent(mockContent, "/etc/polkit-1/rules.d/99-test.rules")

	// We expect exactly 2 findings: Vulnerable Rule 1 and Vulnerable Rule 2.
	// All the safe/administrative rules (wheel, sudo, root, comments) must be skipped.
	if len(results) != 2 {
		t.Fatalf("expected exactly 2 vulnerable rules flagged, got %d: %v", len(results), results)
	}

	// Verify the findings
	hasVulnerable1 := false
	hasVulnerable2 := false

	for _, r := range results {
		if r.Action == "org.freedesktop.udisks2.filesystem-mount" && r.Authorized == "Group: users" {
			hasVulnerable1 = true
		}
		if r.Action == "org.libvirt.api.connect.getattr" && r.Authorized == "Any User" {
			hasVulnerable2 = true
		}
	}

	if !hasVulnerable1 {
		t.Error("failed to flag vulnerable rule 1 (Group: users Mount authorization)")
	}
	if !hasVulnerable2 {
		t.Error("failed to flag vulnerable rule 2 (Any User unconditional libvirt authorization)")
	}
}

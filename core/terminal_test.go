package core

import (
	"strings"
	"testing"
)

func TestGetTerminalWidth(t *testing.T) {
	width, _ := GetTerminalWidth()
	if width < 60 || width > 120 {
		t.Errorf("Expected clamped width between 60 and 120, got %d", width)
	}
}

func TestWrapTextShort(t *testing.T) {
	text := "Short line of text"
	wrapped := WrapText(text, 80, "  ")
	if wrapped != "Short line of text" {
		t.Errorf("Expected unchanged text, got %q", wrapped)
	}
}

func TestWrapTextUnbrokenPathNotSplit(t *testing.T) {
	longPath := "/var/lib/docker/overlay2/longidentifier1234567890abcdefghijklmnopqrstuvwxyz/diff/usr/bin/python3"
	text := "Found binary at " + longPath
	wrapped := WrapText(text, 40, "  ")

	// Ensure the long uninterrupted path was not chopped up mid-word
	if !strings.Contains(wrapped, longPath) {
		t.Errorf("Expected full longPath to be preserved without mid-word splitting, got:\n%s", wrapped)
	}
}

func TestWrapTextMultiline(t *testing.T) {
	text := "This is a long sentence intended to test dynamic wrapping of strings in terminal presentation mode without breaking words or breaking line structures."
	indent := "    "
	wrapped := WrapText(text, 50, indent)

	lines := strings.Split(wrapped, "\n")
	if len(lines) < 2 {
		t.Errorf("Expected multiple lines after wrapping, got %d", len(lines))
	}

	for i, line := range lines {
		if i > 0 && !strings.HasPrefix(line, indent) {
			t.Errorf("Line %d missing indentation %q: %s", i, indent, line)
		}
	}
}

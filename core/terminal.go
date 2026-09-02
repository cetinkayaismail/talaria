package core

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// GetTerminalWidth queries the kernel directly via the standard TIOCGWINSZ ioctl.
// It requires zero external tools (no stty, tput, ncurses) and runs on bare Alpine,
// BusyBox, and musl. If stdout is not a TTY (pipe, file, dumb terminal), it falls back
// to COLUMNS environment variable or 80 columns.
func GetTerminalWidth() (int, bool) {
	ws := &winsize{}

	// Test stdout (fd 1), fallback to stderr (fd 2), then stdin (fd 0)
	for _, fd := range []uintptr{os.Stdout.Fd(), os.Stderr.Fd(), os.Stdin.Fd()} {
		_, _, err := syscall.Syscall(
			syscall.SYS_IOCTL,
			fd,
			uintptr(syscall.TIOCGWINSZ),
			uintptr(unsafe.Pointer(ws)),
		)
		if err == 0 && ws.Col > 0 {
			w := int(ws.Col)
			// Clamp to ergonomic bounds: minimum 60 to prevent negative margins,
			// maximum 120 so lines don't stretch uncomfortably on ultrawide monitors.
			if w < 60 {
				w = 60
			} else if w > 120 {
				w = 120
			}
			return w, true
		}
	}

	// Fallback 1: Check COLUMNS environment variable
	if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols > 0 {
		if cols < 60 {
			cols = 60
		} else if cols > 120 {
			cols = 120
		}
		return cols, false
	}

	// Fallback 2: Standard POSIX default for pipes/redirects
	return 80, false
}

// IsTerminal checks whether stdout is a character device (interactive terminal)
func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ShouldUseColor checks whether ANSI colors should be emitted.
// Complies with the NO_COLOR standard (https://no-color.org) and checks TTY status.
func ShouldUseColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return IsTerminal()
}

// WrapText wraps text along whitespace boundaries to fit within maxWidth.
// It guarantees that long unbroken strings (such as filesystem paths or hashes)
// are NEVER split mid-word, preserving copy-pasteability and grep matching.
func WrapText(text string, maxWidth int, indent string) string {
	if maxWidth <= len(indent)+10 {
		return indent + text
	}

	usableWidth := maxWidth - len(indent)
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= usableWidth {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)

	return strings.Join(lines, "\n"+indent)
}

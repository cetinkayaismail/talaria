.PHONY: all build build-static test test-race vet fmt verify clean run

GO ?= $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
BINARY_NAME=talaria

all: build

build:
	@echo "=> Compiling Talaria (Standard)..."
	$(GO) build -trimpath -ldflags="-s -w -buildid=" -o $(BINARY_NAME) main.go
	@echo "=> Build complete: ./$(BINARY_NAME)"

build-static:
	@echo "=> Compiling Talaria (Statically Linked, CGO Disabled)..."
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -buildid= -extldflags '-static'" -o $(BINARY_NAME) main.go
	@echo "=> Static build complete: ./$(BINARY_NAME)"

test:
	@echo "=> Running test suite..."
	$(GO) test -v ./...

test-race:
	@echo "=> Running test suite with race detector..."
	$(GO) test -count=1 -race ./...

vet:
	@echo "=> Running go vet..."
	$(GO) vet ./...

fmt:
	@echo "=> Formatting Go code..."
	$(GO) fmt ./...

verify: fmt vet test-race
	@echo "=> All enterprise quality checks passed successfully."

clean:
	@echo "=> Cleaning up build and test artifacts..."
	rm -f $(BINARY_NAME) $(BINARY_NAME).gz coverage.* *.test *.out profile.cov
	@echo "=> Clean complete."

run: build
	./$(BINARY_NAME) --scan all

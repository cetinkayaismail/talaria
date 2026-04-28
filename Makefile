.PHONY: all build clean run

BINARY_NAME=talaria

all: build

build:
	@echo "=> Compiling Talaria (Statically Linked)..."
	CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o $(BINARY_NAME) main.go
	@echo "=> Build complete. You can now run ./$(BINARY_NAME)"

clean:
	@echo "=> Cleaning up..."
	rm -f $(BINARY_NAME)
	@echo "=> Clean complete."

run: build
	./$(BINARY_NAME) -scan all

BIN := bin

.PHONY: build install test vet clean

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/dep      ./cmd/dep
	go build -o $(BIN)/dep-mcp  ./cmd/dep-mcp

install: build
	cp $(BIN)/dep     ~/.local/bin/dep
	cp $(BIN)/dep-mcp ~/.local/bin/dep-mcp

test:
	go test ./... -count=1 -timeout 120s

vet:
	go vet ./...

clean:
	rm -rf $(BIN)

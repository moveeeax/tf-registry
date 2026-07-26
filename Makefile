BINARY  := tf-registry
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test race vet fmt validate clean

all: vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/tf-registry

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# The pre-publish gate, run against the fixture catalog.
validate: build
	./$(BINARY) validate -catalog examples/catalog -key examples/keys/cosign.pub

clean:
	rm -f $(BINARY)
	rm -rf dist

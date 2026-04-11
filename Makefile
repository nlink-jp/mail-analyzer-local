VERSION ?= dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test clean

build:
	@mkdir -p dist
	go build -ldflags "$(LDFLAGS)" -o dist/mail-analyzer-local .

test:
	go test ./...

clean:
	rm -rf dist

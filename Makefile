VERSION ?= dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION)
BINARY  := mail-analyzer-local

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: build build-all test clean

build:
	@mkdir -p dist
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY) .

build-all:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext . && \
		zip -j dist/$(BINARY)-$$os-$$arch.zip \
			dist/$(BINARY)-$$os-$$arch$$ext README.md; \
	done

test:
	go test ./...

clean:
	rm -rf dist

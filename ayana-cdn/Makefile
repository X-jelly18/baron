# Convenience targets for development. The installer (deploy/install.sh)
# does not use make.
GO      ?= go
VERSION := $(shell sed -nE 's/^var version = "([^"]+)"/\1/p' cmd/ayana-cdn/server.go)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race vet install clean

build:            ## build ./bin/ayana-cdn
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/ayana-cdn ./cmd/ayana-cdn

test:             ## unit and integration tests (about 5 s)
	$(GO) test -count=1 ./...

race:             ## the same under the race detector, three times
	$(GO) test -race -count=3 ./...

vet:              ## go vet and gofmt
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd)" || { gofmt -l cmd; echo "run gofmt"; exit 1; }

install:          ## build on this machine and install/upgrade the service
	sudo ./deploy/install.sh

clean:
	rm -rf bin

BINARY := posture
PKG := ./cmd/posture

.DEFAULT_GOAL := help

.PHONY: help build test test-kind vet fmt clean install

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the posture binary in the current directory
	go build -o $(BINARY) $(PKG)

test: ## Run unit tests
	go test ./...

test-kind: ## Create a disposable kind cluster and run the live fixture test
	go test -tags kind -count=1 -timeout 25m ./test/kind/

vet: ## Run go vet
	go vet ./...

fmt: ## Format Go source
	gofmt -w ./cmd ./internal

clean: ## Remove the built binary and generated reports
	rm -f $(BINARY)
	rm -rf posture-report-*

install: ## Install posture onto PATH (GOBIN or GOPATH/bin)
	go install $(PKG)

SHELL := /bin/sh

GO ?= go
GOLANGCI_LINT ?= golangci-lint
DOCKER ?= docker

MODULE := github.com/Naenier/opsdoctor
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODIFIED ?= $(shell if test -n "$$(git status --porcelain --untracked-files=normal 2>/dev/null)"; then printf '%s' true; else printf '%s' false; fi)
IMAGE ?= opsdoctor:dev
GUI_TAGS ?= migrated_fynedo

LDFLAGS := -s -w -buildid= \
	-X $(MODULE)/internal/buildinfo.commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.buildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/buildinfo.modified=$(MODIFIED)
BUILD_FLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.DEFAULT_GOAL := help

.PHONY: help fmt fmt-check vet lint test test-race coverage build build-cli build-gui
.PHONY: run-cli run-gui docker-build docker-run clean

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target> [ARGS=\"...\"]\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format all Go packages.
	$(GO) fmt ./...

fmt-check: ## Check that Go source files are formatted.
	./scripts/check-format.sh

vet: ## Run the Go static analyzer.
	$(GO) vet ./...

lint: ## Run golangci-lint using .golangci.yml.
	$(GOLANGCI_LINT) run ./...

test: ## Run unit tests.
	$(GO) test ./...

test-race: ## Run unit tests with the race detector.
	$(GO) test -race ./...

coverage: ## Write an atomic coverage profile to coverage.out.
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./...

build: build-cli build-gui ## Build both application entry points.

build-cli: ## Build the command-line application.
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o bin/opsdoctor ./cmd/opsdoctor

build-gui: ## Build the desktop application for the current platform.
	mkdir -p bin
	$(GO) build -tags "$(GUI_TAGS)" $(BUILD_FLAGS) -o bin/opsdoctor-desktop ./cmd/opsdoctor-desktop

run-cli: ## Run the CLI; pass arguments with ARGS.
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/opsdoctor $(ARGS)

run-gui: ## Run the desktop application.
	$(GO) run -tags "$(GUI_TAGS)" -ldflags "$(LDFLAGS)" ./cmd/opsdoctor-desktop

docker-build: ## Build the non-root CLI container image.
	$(DOCKER) build \
		--build-arg COMMIT="$(COMMIT)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg MODIFIED="$(MODIFIED)" \
		--tag "$(IMAGE)" \
		.

docker-run: ## Run the CLI container; pass arguments with ARGS.
	$(DOCKER) run --rm "$(IMAGE)" $(ARGS)

clean: ## Remove generated build and test output.
	rm -rf -- ./bin ./dist ./coverage.out

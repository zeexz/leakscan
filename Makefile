# ============================================================
#  leakscan – project task automation
#  Usage: make <target>  (run 'make help' to list all targets)
# ============================================================

# ── Build metadata ──────────────────────────────────────────
BINARY_NAME  := leakscan
MODULE       := leakscan
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE         := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
LDFLAGS      := -ldflags="-s -w \
	-X '$(MODULE)/cmd.Version=$(VERSION)' \
	-X '$(MODULE)/cmd.Commit=$(COMMIT)' \
	-X '$(MODULE)/cmd.BuildDate=$(DATE)'"

# ── Directories ─────────────────────────────────────────────
DIST_DIR     := dist
COVER_FILE   := coverage.out
COVER_HTML   := coverage.html

# ── Fuzz settings (override with: make test-fuzz FUZZ_TIME=60s) ─
FUZZ_TIME    ?= 30s

# ── Tools ────────────────────────────────────────────────────
GOLANGCI_LINT := golangci-lint

# ────────────────────────────────────────────────────────────
#  Targets
# ────────────────────────────────────────────────────────────

.PHONY: all
all: lint test build  ## Run lint, test, then build (default CI pipeline)

# ── Build ────────────────────────────────────────────────────
.PHONY: build
build:  ## Compile binary with version metadata into ./$(BINARY_NAME)
	@echo "▶ Building $(BINARY_NAME) $(VERSION) ($(COMMIT))..."
	go build $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "✔ Binary: ./$(BINARY_NAME)"

# ── Install ──────────────────────────────────────────────────
.PHONY: install
install:  ## Install binary into $$GOPATH/bin
	@echo "▶ Installing $(BINARY_NAME) to $$GOPATH/bin..."
	go install $(LDFLAGS) .
	@echo "✔ Installed."

# ── Test (with race detector + coverage) ─────────────────────
.PHONY: test
test:  ## Run all unit tests with race detector and generate coverage.out
	@echo "▶ Running tests (race detector enabled)..."
	go test -race -count=1 -coverprofile=$(COVER_FILE) -covermode=atomic ./...
	@echo "✔ Coverage written to $(COVER_FILE)"
	@go tool cover -func=$(COVER_FILE) | tail -1

# ── Coverage HTML report ─────────────────────────────────────
.PHONY: coverage
coverage: test  ## Generate and open an HTML coverage report
	go tool cover -html=$(COVER_FILE) -o $(COVER_HTML)
	@echo "✔ HTML report: $(COVER_HTML)"
	# Open in default browser (cross-platform best-effort)
	@open $(COVER_HTML) 2>/dev/null || xdg-open $(COVER_HTML) 2>/dev/null || start $(COVER_HTML) 2>/dev/null || true

# ── Fuzz testing ─────────────────────────────────────────────
.PHONY: test-fuzz
test-fuzz:  ## Run all fuzz targets for $(FUZZ_TIME) each (default: 30s)
	@echo "▶ Fuzzing FuzzRegexDetector_NoPanic for $(FUZZ_TIME)..."
	go test -fuzz=FuzzRegexDetector_NoPanic \
	        -fuzztime=$(FUZZ_TIME) \
	        ./internal/detector/
	@echo "▶ Fuzzing FuzzLoadRulesFromYAML_NoPanic for $(FUZZ_TIME)..."
	go test -fuzz=FuzzLoadRulesFromYAML_NoPanic \
	        -fuzztime=$(FUZZ_TIME) \
	        ./internal/detector/
	@echo "✔ Fuzz run complete. Corpus saved under testdata/fuzz/."

# ── Lint ─────────────────────────────────────────────────────
.PHONY: lint
lint:  ## Run golangci-lint with project config (.golangci.yml)
	@echo "▶ Running golangci-lint..."
	$(GOLANGCI_LINT) run ./...
	@echo "✔ Lint passed."

# ── Lint (auto-fix where possible) ───────────────────────────
.PHONY: lint-fix
lint-fix:  ## Run golangci-lint with --fix to auto-correct style issues
	$(GOLANGCI_LINT) run --fix ./...

# ── Vet ──────────────────────────────────────────────────────
.PHONY: vet
vet:  ## Run go vet on all packages
	go vet ./...

# ── Tidy ─────────────────────────────────────────────────────
.PHONY: tidy
tidy:  ## Tidy go.mod / go.sum
	go mod tidy

# ── Clean ────────────────────────────────────────────────────
.PHONY: clean
clean:  ## Remove compiled binary, dist/, and coverage files
	@echo "▶ Cleaning build artefacts..."
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f $(COVER_FILE) $(COVER_HTML)
	rm -rf $(DIST_DIR)/
	@echo "✔ Clean."

# ── GoReleaser dry-run ────────────────────────────────────────
.PHONY: snapshot
snapshot:  ## Build a local snapshot release (no publish) via GoReleaser
	goreleaser release --snapshot --clean

# ── Help ─────────────────────────────────────────────────────
.PHONY: help
help:  ## Display this help message
	@echo ""
	@echo "  leakscan – available make targets"
	@echo "  ──────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

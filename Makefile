BIN_NAME  := aikey
VERSION   := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
CARGO     := $(shell command -v cargo 2>/dev/null || echo $$HOME/.cargo/bin/cargo)

.PHONY: all release dev rebuild run test test-integration test-unit test-verbose \
        lint fmt fmt-check install uninstall cross-compile clean help

# Default: release build (production-ready)
all: release

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## Build optimized release binary  →  target/release/aikey
release:
	$(CARGO) build --release

## Build debug binary (fast iteration)  →  target/debug/aikey
dev:
	$(CARGO) build

## Force full recompile (clean + release)
rebuild:
	$(CARGO) clean
	$(CARGO) build --release

## Run release binary
run: release
	./target/release/$(BIN_NAME)

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

## Run all tests
test:
	$(CARGO) test

## Run integration tests only
test-integration:
	$(CARGO) test --test '*'

## Run unit tests only
test-unit:
	$(CARGO) test --lib

## Run tests with output visible
test-verbose:
	$(CARGO) test -- --nocapture

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

## Lint with clippy (warnings as errors)
lint:
	$(CARGO) clippy -- -D warnings

## Auto-format source
fmt:
	$(CARGO) fmt

## Format check (CI)
fmt-check:
	$(CARGO) fmt -- --check

# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

## Install release binary to ~/.cargo/bin
install: release
	$(CARGO) install --path .

## Remove installed binary
uninstall:
	$(CARGO) uninstall aikeylabs-aikey-cli 2>/dev/null || true

# ---------------------------------------------------------------------------
# Cross-compile
# ---------------------------------------------------------------------------

CROSS_OUT := target/cross

## Build release binaries for macOS / Linux / Windows
cross-compile:
	@mkdir -p $(CROSS_OUT)
	$(CARGO) build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/$(BIN_NAME)     $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-darwin-arm64
	$(CARGO) build --release --target x86_64-apple-darwin
	cp target/x86_64-apple-darwin/release/$(BIN_NAME)      $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-darwin-amd64
	$(CARGO) build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/$(BIN_NAME) $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-linux-amd64
	$(CARGO) build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/$(BIN_NAME).exe $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-windows-amd64.exe
	@echo "Binaries written to $(CROSS_OUT)/"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

## Remove build artifacts
clean:
	$(CARGO) clean

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

## Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build:"
	@printf "  %-22s %s\n" "make / make release" "Release binary (default)"
	@printf "  %-22s %s\n" "make dev"            "Debug binary (fast iteration)"
	@printf "  %-22s %s\n" "make rebuild"        "Force full recompile"
	@printf "  %-22s %s\n" "make run"            "Build release and run"
	@echo ""
	@echo "Test:"
	@printf "  %-22s %s\n" "make test"           "All tests"
	@printf "  %-22s %s\n" "make test-unit"      "Unit tests only"
	@printf "  %-22s %s\n" "make test-integration" "Integration tests only"
	@printf "  %-22s %s\n" "make test-verbose"   "Tests with stdout visible"
	@echo ""
	@echo "Quality:"
	@printf "  %-22s %s\n" "make lint"           "Clippy (warnings as errors)"
	@printf "  %-22s %s\n" "make fmt"            "Auto-format source"
	@printf "  %-22s %s\n" "make fmt-check"      "Format check (CI)"
	@echo ""
	@echo "Install:"
	@printf "  %-22s %s\n" "make install"        "Install to ~/.cargo/bin"
	@printf "  %-22s %s\n" "make uninstall"      "Remove installed binary"
	@printf "  %-22s %s\n" "make cross-compile"  "All platform binaries"
	@printf "  %-22s %s\n" "make clean"          "Remove build artifacts"
	@echo ""
	@echo "Version: $(VERSION)"

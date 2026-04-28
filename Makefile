BIN_NAME  := aikey
VERSION   := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
CARGO     := $(shell command -v cargo 2>/dev/null || echo $$HOME/.cargo/bin/cargo)

# ---------------------------------------------------------------------------
# Buildinfo variables (passed as env vars to cargo build)
# ---------------------------------------------------------------------------
GIT_REVISION  = $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY     = $(shell test -z "$$(git status --porcelain --untracked-files=normal 2>/dev/null)" && echo "" || echo "-dirty")
BUILD_ID     ?= $(shell head -c 2 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null \
                  || powershell -NoProfile -C "'{0:x4}' -f (Get-Random -Max 65535)" 2>/dev/null \
                  || echo "0000")
BUILD_TIME    = $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                  || powershell -NoProfile -C "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')" 2>/dev/null \
                  || echo "unknown")
# AIKEY_BUILD_VERSION default = Cargo.toml's `version` (already parsed into
# $(VERSION) at line 2). build.rs uses this env to override CARGO_PKG_VERSION
# at compile time. Without this default, dev builds (make restart-trial1,
# build-dev-tarballs.sh, plain `make install`) fall through to whatever's in
# Cargo.toml — usually correct after this commit, but easy to drift again.
# Wiring AIKEY_BUILD_VERSION through BUILD_ENV makes Cargo.toml the canonical
# dev-time source; release.sh still wins by exporting AIKEY_BUILD_VERSION in
# its own env before calling cargo, since `?=` defers to existing env value.
# Bugfix record: workflow/CI/bugfix/2026-04-27-aikey-cli-version-banner-stale.md
AIKEY_BUILD_VERSION ?= $(VERSION)
# Why `=` (deferred) not `:=` (immediate): BUILD_ID uses ?= so it can be
# overridden by the parent CI Makefile via env var. With :=, $(BUILD_ID) would
# be evaluated at parse time before the env override takes effect.
BUILD_ENV   = AIKEY_BUILD_VERSION=$(AIKEY_BUILD_VERSION) AIKEY_BUILD_REVISION=$(GIT_REVISION)$(GIT_DIRTY) AIKEY_BUILD_ID=$(BUILD_ID) AIKEY_BUILD_TIME=$(BUILD_TIME)

.PHONY: all release dev rebuild run test test-integration test-unit test-verbose \
        test-import-recall test-proxy-lifecycle-e2e build-mock-proxy \
        e2e-import-personal e2e-import-trial e2e-import-production \
        security-check-batch-import \
        lint fmt fmt-check install uninstall cross-compile clean help

# Default: release build (production-ready)
all: release

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## Build optimized release binary  →  target/release/aikey
release:
	@$(BUILD_ENV) $(CARGO) build --release

## Build debug binary (fast iteration)  →  target/debug/aikey
dev:
	$(BUILD_ENV) $(CARGO) build

## Force full recompile (clean + release)
rebuild:
	$(CARGO) clean
	$(BUILD_ENV) $(CARGO) build --release

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

## Stage 6 — end-to-end Quick Import smoke (per edition).
##
## These targets assume the corresponding installer has been run already
## (local-install.sh / trial-install.sh / server-install.sh) so that the
## port file at ~/.aikey/config/local-server.port exists. They spawn a
## subprocess of the release binary and drive it through:
##    aikey status         (asserts local-server reachable)
##    aikey import <fixt>  (asserts browser URL printed / headless path exits)
## The full UI flow (paste → parse → confirm) is out of scope for these
## smoke targets; that is covered by the browser-click checklist in
## workflow/CD/checklist.md §5.
e2e-import-personal: release
	@echo "→ Personal edition smoke"
	@./target/release/aikey status > /tmp/aikey-e2e-status.out 2>&1 || true
	@grep -E 'local-server: running on port' /tmp/aikey-e2e-status.out \
	    || { echo "FAIL: local-server status line missing"; cat /tmp/aikey-e2e-status.out; exit 1; }
	@echo "test_fixture" > /tmp/aikey-e2e-import-input.txt
	@./target/release/aikey import /tmp/aikey-e2e-import-input.txt --json > /tmp/aikey-e2e-import.out 2>&1 || true
	@grep -E '"status":"ok"' /tmp/aikey-e2e-import.out \
	    || { echo "FAIL: import did not print ok envelope"; cat /tmp/aikey-e2e-import.out; exit 1; }
	@rm -f /tmp/aikey-e2e-import-input.txt /tmp/aikey-e2e-import.out /tmp/aikey-e2e-status.out
	@echo "✓ Personal edition smoke passed"

e2e-import-trial: release
	@echo "→ Team-Trial edition smoke (reuses personal path — same CLI binary)"
	@$(MAKE) e2e-import-personal

e2e-import-production: release
	@echo "→ Production edition smoke (CLI still runs locally, API may 503 in server deployment)"
	@./target/release/aikey status > /tmp/aikey-e2e-status.out 2>&1 || true
	@grep -E 'local-server' /tmp/aikey-e2e-status.out \
	    || { echo "FAIL: status command did not mention local-server"; exit 1; }
	@rm -f /tmp/aikey-e2e-status.out
	@echo "✓ Production edition smoke passed (status only)"

## Stage 6 — static security checks for the batch-import surface.
##
## Verifies the "Go does no AES" boundary (implementation plan §6.7). Runs as
## plain grep; any hit = reject. Intended to run in CI on every PR that
## touches internal/api/user/importpkg or aikey-cli/src/commands_import.
security-check-batch-import:
	@echo "→ importpkg must not import crypto/aes or crypto/cipher"
	@! grep -rE '"crypto/aes"|"crypto/cipher"' \
	    ../aikey-control/service/internal/api/user/importpkg/ 2>/dev/null \
	    || { echo "FAIL: AES import found in importpkg"; exit 1; }
	@echo "→ importpkg must not import aikey-proxy vault package"
	@! grep -r 'aikey-proxy/internal/vault' \
	    ../aikey-control/service/internal/api/user/importpkg/ 2>/dev/null \
	    || { echo "FAIL: importpkg leaks proxy vault coupling"; exit 1; }
	@echo "→ cli must not log vault_key_hex / password plaintext"
	@! grep -rnE 'eprintln!.*vault_key|println!.*vault_key|eprintln!.*password|println!.*password' \
	    src/commands_import.rs src/commands_internal/ 2>/dev/null \
	    || { echo "FAIL: vault key / password logged"; exit 1; }
	@echo "✓ Static security checks pass"

## Import-recall regression suite (Stage 3 parse engine)
##   - rule v2 recall gates (in_dist / ood_layouts / ood_apikey / ood_realworld)
##   - CRF rescue layer (in_dist 100%, adversarial FP<=1)
##   - Provider fingerprint accuracy (ood_apikey / ood_realworld)
##   - Pipeline E2E golden (all 56 positive samples, full recall)
##   - Fingerprint coverage audit (22 providers)
##
##   Release mode to exercise the same binary path CLI users hit.
##   Prints per-test [rule-v2] / [crf] / [fingerprint] summary lines.
test-import-recall:
	@$(BUILD_ENV) $(CARGO) test --release --test import_recall -- --nocapture --test-threads=1

## Build the controlled-behavior mock_proxy Go binary used by lifecycle E2E
## tests for scenarios the real proxy cannot easily emulate (BIND_FAIL,
## HANG_INIT, DRAIN_DELAY, IGNORE_SIGTERM). Cached at target/test-bin/mock_proxy.
##
## Per E2E plan v6 §3.4 fallback strategy: if Go toolchain is missing,
## the lifecycle E2E tests degrade to the "real-proxy-only" subset and
## skip mock-dependent cases.
build-mock-proxy:
	@mkdir -p target/test-bin
	@if command -v go >/dev/null 2>&1; then \
	  echo "[build-mock-proxy] using $$(go version)"; \
	  cd tests/lifecycle_fixtures/mock_proxy && \
	    GOWORK=off go build -o ../../../target/test-bin/mock_proxy . && \
	    echo "[build-mock-proxy] built target/test-bin/mock_proxy"; \
	else \
	  echo "[build-mock-proxy] Go toolchain missing — mock-dependent E2E tests will skip (per v6 §3.4)"; \
	fi

## Run the proxy lifecycle E2E acceptance suite (v6 plan §4 + Round-10 baseline).
## Uses real aikey-proxy from $$HOME/.aikey/bin/aikey-proxy + mock_proxy from
## target/test-bin/. Tests are Unix-only by design (v6 §5 platform matrix);
## Windows runners run the regression baseline subset only.
##
## Serial execution (--test-threads=1) is mandatory: lifecycle tests share
## ~/.aikey/run/proxy.{pid,lock,meta.json} files in their per-test HOME, but
## port allocation via pick_free_port() needs serialization to avoid TOCTOU.
test-proxy-lifecycle-e2e: build-mock-proxy
	@AIKEY_PROXY_BIN="$${AIKEY_PROXY_BIN:-$$HOME/.aikey/bin/aikey-proxy}" \
	  $(CARGO) test --test e2e_proxy_lifecycle -- --test-threads=1 && \
	 AIKEY_PROXY_BIN="$${AIKEY_PROXY_BIN:-$$HOME/.aikey/bin/aikey-proxy}" \
	  $(CARGO) test --test e2e_proxy_lifecycle_v6 -- --test-threads=1

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

## Install release binary to ~/.aikey/bin (ad-hoc signed on macOS)
install: release
	@mkdir -p $(HOME)/.aikey/bin
	@cp target/release/$(BIN_NAME) $(HOME)/.aikey/bin/$(BIN_NAME)
	@chmod 755 $(HOME)/.aikey/bin/$(BIN_NAME)
ifeq ($(shell uname -s),Darwin)
	@xattr -d com.apple.provenance $(HOME)/.aikey/bin/$(BIN_NAME) 2>/dev/null || true
	@codesign -fs - $(HOME)/.aikey/bin/$(BIN_NAME) 2>/dev/null || true
	@echo "macOS: cleared provenance & re-signed"
endif
	@echo "Installed: $(HOME)/.aikey/bin/$(BIN_NAME)"

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
	$(BUILD_ENV) $(CARGO) build --release --target aarch64-apple-darwin
	cp target/aarch64-apple-darwin/release/$(BIN_NAME)     $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-darwin-arm64
	$(BUILD_ENV) $(CARGO) build --release --target x86_64-apple-darwin
	cp target/x86_64-apple-darwin/release/$(BIN_NAME)      $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-darwin-amd64
	$(BUILD_ENV) $(CARGO) build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/$(BIN_NAME) $(CROSS_OUT)/$(BIN_NAME)-$(VERSION)-linux-amd64
	$(BUILD_ENV) $(CARGO) build --release --target x86_64-pc-windows-gnu
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
	@printf "  %-22s %s\n" "make test-import-recall" "Stage 3 parse engine recall + fingerprint gates"
	@printf "  %-22s %s\n" "make e2e-import-personal" "Stage 6 e2e: status + aikey import smoke"
	@printf "  %-22s %s\n" "make e2e-import-trial" "  (alias — same binary as personal)"
	@printf "  %-22s %s\n" "make e2e-import-production" "Stage 6 e2e: status only (no local API)"
	@printf "  %-22s %s\n" "make security-check-batch-import" "Stage 6 static security gate (AES / vault key)"
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

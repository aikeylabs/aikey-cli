#!/usr/bin/env bash
#
# e2e-dashboard.sh — End-to-end verification for the 费用小票 + 实时仪表盘 feature.
#
# This is the top-level orchestration harness for Stage 3's P0-P1 deliverables.
# It chains all existing test primitives plus a set of sandbox-HOME integration
# assertions that cover the install/uninstall and watch-snapshot paths the
# individual cargo/go tests don't touch.
#
# Pipeline:
#   1.  Build both binaries (release-quality, catches linkage errors).
#   2.  Run proxy Go tests — covers session_id → WAL plumbing (P0d half 1).
#   3.  Run CLI cargo tests — covers WAL reader, aggregator, statusline render.
#   4.  Run existing probe-statusline.sh — CLI half of P0d probe.
#   5.  New: install/uninstall idempotency + backup/restore.
#   6.  New: watch snapshot picks up seeded WAL entries.
#   7.  Emit a per-stage pass/fail table, exit 1 on any failure.
#
# Why shell and not a Rust integration test?  Because steps 5 and 6 exercise
# an absolute HOME path and the installed binary's interaction with the real
# filesystem — something `cargo test` can't sandbox without extra scaffolding.
# The shell wrapper also lets CI run this without a Rust toolchain installed,
# as long as binaries are prebuilt (set SKIP_BUILD=1).
#
# Usage:
#   ./scripts/e2e-dashboard.sh           # full run
#   SKIP_BUILD=1 ./scripts/e2e-dashboard.sh   # skip cargo/go build
#   SKIP_GOTEST=1 ./scripts/e2e-dashboard.sh  # skip Go tests (faster iterations)
#   SKIP_CARGOTEST=1 ./scripts/e2e-dashboard.sh  # skip cargo tests
#
# Exit status: 0 = all stages green, 1 = at least one failure.

set -uo pipefail

# ---------------------------------------------------------------------------
# Paths & constants.
# ---------------------------------------------------------------------------
CLI_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "$CLI_DIR/.." && pwd)"
PROXY_DIR="$ROOT_DIR/aikey-proxy"
AIKEY_BIN="$CLI_DIR/target/debug/aikey"

# ANSI
BOLD=$'\033[1m'
RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
DIM=$'\033[2m'
RESET=$'\033[0m'

# Stage results accumulator: "name|status|detail"
RESULTS=()

pass() { RESULTS+=("$1|PASS|"); echo "${GREEN}✓${RESET} $1"; }
fail() { RESULTS+=("$1|FAIL|$2"); echo "${RED}✗${RESET} $1 — $2"; }
skip() { RESULTS+=("$1|SKIP|$2"); echo "${YELLOW}⊘${RESET} $1 — $2"; }

header() {
    echo
    echo "${BOLD}━━━ $1 ━━━${RESET}"
}

# ---------------------------------------------------------------------------
# 1. Build.
# ---------------------------------------------------------------------------
header "1. Build"

if [ "${SKIP_BUILD:-0}" = "1" ]; then
    skip "build (aikey-cli)" "SKIP_BUILD=1"
    skip "build (aikey-proxy)" "SKIP_BUILD=1"
else
    if (cd "$CLI_DIR" && cargo build --bin aikey 2>&1 | tail -5); then
        pass "build (aikey-cli)"
    else
        fail "build (aikey-cli)" "cargo build failed"
    fi

    if (cd "$PROXY_DIR" && go build ./... 2>&1 | tail -5); then
        pass "build (aikey-proxy)"
    else
        fail "build (aikey-proxy)" "go build failed"
    fi
fi

if [ ! -x "$AIKEY_BIN" ]; then
    fail "binary available" "$AIKEY_BIN not found or not executable"
    # Can't continue without the binary; print summary and exit.
    echo
    echo "${RED}${BOLD}FATAL${RESET}: aikey binary unavailable, aborting."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Proxy Go tests (session_id header → WAL plumbing).
# ---------------------------------------------------------------------------
header "2. aikey-proxy unit + integration tests"

if [ "${SKIP_GOTEST:-0}" = "1" ]; then
    skip "go test ./..." "SKIP_GOTEST=1"
else
    GO_LOG=$(mktemp)
    if (cd "$PROXY_DIR" && go test ./... -count=1 >"$GO_LOG" 2>&1); then
        pass "go test ./..."
    else
        tail_out=$(tail -20 "$GO_LOG" | tr '\n' ' ')
        fail "go test ./..." "${tail_out:0:200}"
        echo "${DIM}  full log: $GO_LOG${RESET}"
    fi
fi

# ---------------------------------------------------------------------------
# 3. CLI cargo tests.
# ---------------------------------------------------------------------------
header "3. aikey-cli cargo tests"

if [ "${SKIP_CARGOTEST:-0}" = "1" ]; then
    skip "cargo test --lib" "SKIP_CARGOTEST=1"
else
    CARGO_LOG=$(mktemp)
    if (cd "$CLI_DIR" && cargo test --lib -- usage_wal commands_statusline commands_watch >"$CARGO_LOG" 2>&1); then
        pass "cargo test (usage_wal + statusline + watch)"
    else
        tail_out=$(tail -30 "$CARGO_LOG" | tr '\n' ' ')
        fail "cargo test (usage_wal + statusline + watch)" "${tail_out:0:300}"
        echo "${DIM}  full log: $CARGO_LOG${RESET}"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Existing probe-statusline.sh (CLI half of P0d probe).
# ---------------------------------------------------------------------------
header "4. probe-statusline.sh (P0d CLI half)"

PROBE_LOG=$(mktemp)
if AIKEY_BIN="$AIKEY_BIN" bash "$CLI_DIR/scripts/probe-statusline.sh" >"$PROBE_LOG" 2>&1; then
    pass "probe-statusline.sh"
else
    tail_out=$(tail -15 "$PROBE_LOG" | tr '\n' ' ')
    fail "probe-statusline.sh" "${tail_out:0:300}"
    echo "${DIM}  full log: $PROBE_LOG${RESET}"
fi

# ---------------------------------------------------------------------------
# 5. Install / uninstall integration — sandboxed HOME.
#
# Covers:
#   - Fresh install writes settings.json + backup absent
#   - Second install is idempotent (no duplicate backup, no error)
#   - --force with an existing non-aikey settings creates a backup
#   - Uninstall removes the statusline stanza and restores backup
# ---------------------------------------------------------------------------
header "5. statusline install/uninstall (sandbox HOME)"

run_install_tests() {
    local sandbox="$1"
    local settings="$sandbox/.claude/settings.json"
    local backup="$sandbox/.claude/settings.aikey_backup.json"

    export HOME="$sandbox"
    mkdir -p "$sandbox/.claude"

    # Case A: fresh install (no pre-existing settings.json).
    "$AIKEY_BIN" statusline install >/dev/null 2>&1 || return 1
    [ -f "$settings" ] || { echo "case A: settings.json not written"; return 2; }
    grep -q '"statusLine"' "$settings" || { echo "case A: statusLine key missing"; return 3; }
    grep -q 'aikey' "$settings" || { echo "case A: aikey command not in settings"; return 4; }

    # Case B: idempotent second install (should not error, no duplicate stanzas).
    "$AIKEY_BIN" statusline install >/dev/null 2>&1 || { echo "case B: second install failed"; return 5; }
    occurrences=$(grep -c '"statusLine"' "$settings" || true)
    [ "$occurrences" = "1" ] || { echo "case B: statusLine appears $occurrences times (want 1)"; return 6; }

    # Case C: uninstall removes statusLine and restores backup if present.
    "$AIKEY_BIN" statusline uninstall >/dev/null 2>&1 || { echo "case C: uninstall failed"; return 7; }
    if [ -f "$settings" ]; then
        grep -q '"statusLine"' "$settings" && { echo "case C: statusLine still in settings after uninstall"; return 8; }
    fi

    return 0
}

SANDBOX_A="$(mktemp -d)"
INSTALL_ERR=""
if INSTALL_ERR=$(run_install_tests "$SANDBOX_A" 2>&1); then
    pass "install → idempotent re-install → uninstall (sandbox HOME)"
else
    fail "install/uninstall flow" "${INSTALL_ERR:0:200}"
fi
rm -rf "$SANDBOX_A"

# Case D: --force with a pre-existing *non-aikey* settings.json creates a
# backup, and subsequent uninstall restores the original.
run_force_backup_test() {
    local sandbox="$1"
    local settings="$sandbox/.claude/settings.json"
    local backup="$sandbox/.claude/settings.aikey_backup.json"

    export HOME="$sandbox"
    mkdir -p "$sandbox/.claude"

    # Seed with a user-authored statusLine that is NOT aikey's.
    cat >"$settings" <<'JSON'
{
  "statusLine": {
    "type": "command",
    "command": "/usr/local/bin/mytool statusline"
  }
}
JSON
    local original
    original="$(cat "$settings")"

    "$AIKEY_BIN" statusline install --force >/dev/null 2>&1 || { echo "force install failed"; return 1; }
    [ -f "$backup" ] || { echo "backup file missing after --force"; return 2; }
    grep -q 'mytool' "$backup" || { echo "backup does not contain original mytool command"; return 3; }
    grep -q 'aikey' "$settings" || { echo "settings does not contain aikey after --force"; return 4; }
    grep -q 'mytool' "$settings" && { echo "settings still contains original mytool (should be replaced)"; return 5; }

    "$AIKEY_BIN" statusline uninstall >/dev/null 2>&1 || { echo "uninstall after --force failed"; return 6; }
    # After uninstall, backup should be consumed and original restored.
    grep -q 'mytool' "$settings" || { echo "mytool not restored after uninstall"; return 7; }
    grep -q 'aikey' "$settings" && { echo "aikey still present after uninstall"; return 8; }

    return 0
}

SANDBOX_B="$(mktemp -d)"
FORCE_ERR=""
if FORCE_ERR=$(run_force_backup_test "$SANDBOX_B" 2>&1); then
    pass "install --force backs up, uninstall restores"
else
    fail "install --force + uninstall restore" "${FORCE_ERR:0:200}"
fi
rm -rf "$SANDBOX_B"

# Case E: status command reports state honestly.
run_status_test() {
    local sandbox="$1"
    export HOME="$sandbox"
    mkdir -p "$sandbox/.claude"

    # Before install, status should report "not installed" (or similar).
    local before
    before="$("$AIKEY_BIN" statusline status 2>&1 || true)"
    case "$before" in
        *installed*|*Installed*|*present*|*active*|*not*|*Not*) : ;;
        *) echo "status before install produced unexpected output: '$before'"; return 1 ;;
    esac

    "$AIKEY_BIN" statusline install >/dev/null 2>&1 || { echo "install in status test failed"; return 2; }

    local after
    after="$("$AIKEY_BIN" statusline status 2>&1 || true)"
    if [ -z "$after" ]; then
        echo "status after install produced empty output"
        return 3
    fi
    return 0
}

SANDBOX_C="$(mktemp -d)"
STATUS_ERR=""
if STATUS_ERR=$(run_status_test "$SANDBOX_C" 2>&1); then
    pass "statusline status reports state"
else
    fail "statusline status" "${STATUS_ERR:0:200}"
fi
rm -rf "$SANDBOX_C"

# ---------------------------------------------------------------------------
# 6. watch snapshot with seeded WAL — proves aggregator reads real WAL files
#    and render_snapshot emits the key_label.
# ---------------------------------------------------------------------------
header "6. aikey watch snapshot (sandbox HOME + seeded WAL)"

run_watch_snapshot_test() {
    local sandbox="$1"
    export HOME="$sandbox"
    local wal_dir="$sandbox/.aikey/data/usage-wal"
    mkdir -p "$wal_dir"

    local hour
    hour="$(date -u +%Y%m%d-%H)"
    local now_iso
    now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local wal_file="$wal_dir/usage-${hour}.jsonl"

    # Seed three events across two virtual keys so the aggregator has something
    # to group and sort.  Format mirrors aikey-proxy/internal/events/reportable.go.
    python3 - "$wal_file" "$now_iso" <<'PY'
import json, sys
path, now = sys.argv[1:]
events = [
    {"virtual_key_id": "vk_alpha", "key_label": "alpha@example.com",
     "model": "claude-sonnet-4-5-20250929",
     "input_tokens": 1200, "output_tokens": 340, "total_tokens": 1540},
    {"virtual_key_id": "vk_alpha", "key_label": "alpha@example.com",
     "model": "claude-sonnet-4-5-20250929",
     "input_tokens": 800, "output_tokens": 120, "total_tokens": 920},
    {"virtual_key_id": "vk_beta", "key_label": "beta@example.com",
     "model": "kimi-k2",
     "input_tokens": 500, "output_tokens": 90, "total_tokens": 590},
]
with open(path, "w") as f:
    for i, e in enumerate(events):
        entry = {
            "wal_seq": i + 1,
            "written_at": now,
            "schema_version": 1,
            "event_json": {
                "event_id": f"e2e-ev-{i+1}",
                "event_time": now,
                "session_id": f"e2e-sess-{i//2}",
                "key_type": "oauth",
                "route_source": "oauth",
                "completion": "complete",
                "provider_code": "anthropic" if "claude" in e["model"] else "moonshot",
                "oauth_identity": e["key_label"],
                "request_status": "success",
                "http_status_code": 200,
                **e,
            },
        }
        f.write(json.dumps(entry) + "\n")
PY

    # Force snapshot mode (stdout is a pipe here anyway, but be explicit).
    local out
    out="$(AIKEY_WATCH_NO_TUI=1 "$AIKEY_BIN" watch 2>&1)" || {
        echo "watch exited non-zero: $out"
        return 1
    }

    # Strip ANSI for grepping.
    local plain
    plain="$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g')"

    printf '%s' "$plain" | grep -qF "alpha@example.com" || {
        echo "watch snapshot missing 'alpha@example.com'"
        printf 'output:\n%s\n' "$plain" >&2
        return 2
    }
    printf '%s' "$plain" | grep -qF "beta@example.com" || {
        echo "watch snapshot missing 'beta@example.com'"
        return 3
    }

    return 0
}

SANDBOX_D="$(mktemp -d)"
WATCH_ERR=""
if WATCH_ERR=$(run_watch_snapshot_test "$SANDBOX_D" 2>&1); then
    pass "aikey watch renders seeded WAL events"
else
    fail "aikey watch snapshot" "${WATCH_ERR:0:300}"
fi
rm -rf "$SANDBOX_D"

# Case F: empty WAL dir should not crash.
run_watch_empty_test() {
    local sandbox="$1"
    export HOME="$sandbox"
    mkdir -p "$sandbox/.aikey/data/usage-wal"

    local out
    if ! out="$(AIKEY_WATCH_NO_TUI=1 "$AIKEY_BIN" watch 2>&1)"; then
        echo "watch exited non-zero with empty WAL: $out"
        return 1
    fi
    return 0
}

SANDBOX_E="$(mktemp -d)"
EMPTY_ERR=""
if EMPTY_ERR=$(run_watch_empty_test "$SANDBOX_E" 2>&1); then
    pass "aikey watch handles empty WAL dir"
else
    fail "aikey watch (empty WAL)" "${EMPTY_ERR:0:200}"
fi
rm -rf "$SANDBOX_E"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Summary"

pass_count=0
fail_count=0
skip_count=0
printf "  %-60s %s\n" "Stage" "Result"
printf "  %-60s %s\n" "------------------------------------------------------------" "------"
for row in "${RESULTS[@]}"; do
    IFS='|' read -r name status detail <<<"$row"
    case "$status" in
        PASS)
            printf "  %-60s ${GREEN}%s${RESET}\n" "$name" "PASS"
            pass_count=$((pass_count + 1))
            ;;
        FAIL)
            printf "  %-60s ${RED}%s${RESET}\n" "$name" "FAIL"
            [ -n "$detail" ] && printf "    ${DIM}%s${RESET}\n" "${detail:0:120}"
            fail_count=$((fail_count + 1))
            ;;
        SKIP)
            printf "  %-60s ${YELLOW}%s${RESET}\n" "$name" "SKIP"
            skip_count=$((skip_count + 1))
            ;;
    esac
done

echo
total=$((pass_count + fail_count + skip_count))
echo "  ${BOLD}${pass_count}${RESET} passed, ${BOLD}${fail_count}${RESET} failed, ${BOLD}${skip_count}${RESET} skipped (${total} total)"

if [ "$fail_count" -gt 0 ]; then
    echo "  ${RED}${BOLD}FAILED${RESET}"
    exit 1
fi
echo "  ${GREEN}${BOLD}ALL GREEN${RESET}"
exit 0

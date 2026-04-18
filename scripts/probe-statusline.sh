#!/usr/bin/env bash
#
# probe-statusline.sh — CLI half of the P0d session_id automated probe.
#
# Verifies: given a synthetic WAL entry with session_id=PROBE, the
# `aikey statusline` command can locate that entry via stdin-provided
# session_id and render a receipt containing the event's key_label.
#
# This complements the proxy-side Go test
# (aikey-proxy/internal/proxy/session_id_probe_test.go), which verifies
# the HTTP-header → WAL half.  Together they prove end-to-end plumbing
# WITHOUT requiring a live Claude Code session or tcpdump.
#
# When to run:
#   - Before any release that touches statusline / WAL schema.
#   - As a smoke-test after proxy or CLI refactor.
#
# Exit status: 0 = probe passed, non-zero = plumbing broken.

set -euo pipefail

AIKEY_BIN="${AIKEY_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/aikey}"
if [ ! -x "$AIKEY_BIN" ]; then
    echo "probe: aikey binary not found at $AIKEY_BIN" >&2
    echo "probe: run 'cargo build' in aikey-cli first, or set AIKEY_BIN" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Fresh sandbox HOME so we neither read nor touch the user's real ~/.aikey.
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
export HOME="$SANDBOX"
WAL_DIR="$SANDBOX/.aikey/data/usage-wal"
mkdir -p "$WAL_DIR"

PROBE_SESSION="probe-sess-$(date +%s)"
PROBE_MODEL="claude-sonnet-4-5-20250929"
PROBE_LABEL="aikey-probe@example.com"

# ---------------------------------------------------------------------------
# Write a synthetic WAL entry shaped exactly like the proxy writes (see
# aikey-proxy/internal/events/reportable.go for the schema).  Using the
# current hour ensures `scan_wal_backward`'s newest-first traversal hits
# this file first.
# ---------------------------------------------------------------------------
HOUR="$(date -u +%Y%m%d-%H)"
WAL_FILE="$WAL_DIR/usage-${HOUR}.jsonl"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Build a minimal event.  Fields not needed by statusline are omitted so
# this also exercises the omitempty tolerance in usage_wal.rs.
python3 - "$WAL_FILE" "$NOW_ISO" "$PROBE_SESSION" "$PROBE_LABEL" "$PROBE_MODEL" <<'PY'
import json, sys
path, now, sid, label, model = sys.argv[1:]
entry = {
    "wal_seq": 1,
    "written_at": now,
    "schema_version": 1,
    "event_json": {
        "event_id": "probe-ev-1",
        "event_time": now,
        "session_id": sid,
        "key_label": label,
        "key_type": "oauth",
        "route_source": "oauth",
        "completion": "complete",
        "virtual_key_id": "oauth:probe-acct",
        "provider_code": "anthropic",
        "oauth_identity": label,
        "model": model,
        "input_tokens": 1234,
        "output_tokens": 458,
        "total_tokens": 1692,
        "request_status": "success",
        "http_status_code": 200,
    },
}
with open(path, "w") as f:
    f.write(json.dumps(entry) + "\n")
PY

# ---------------------------------------------------------------------------
# Invoke statusline with stdin JSON mimicking what Claude Code sends.
# ---------------------------------------------------------------------------
STDIN_JSON="$(printf '{"session_id":"%s","model":{"id":"%s"}}' "$PROBE_SESSION" "$PROBE_MODEL")"
OUTPUT="$(printf '%s' "$STDIN_JSON" | "$AIKEY_BIN" statusline 2>/dev/null || true)"

fail() {
    echo "probe FAILED: $1" >&2
    echo "---" >&2
    echo "wal_file: $WAL_FILE" >&2
    echo "stdin:    $STDIN_JSON" >&2
    echo "output:   '${OUTPUT}'" >&2
    exit 1
}

# Strip ANSI escapes for simpler greps.
plain="$(printf '%s' "$OUTPUT" | sed 's/\x1b\[[0-9;]*m//g')"

# render_line shortens long labels (see shorten_label()), so check the
# @domain suffix which always survives email collapse.
PROBE_LABEL_DOMAIN="${PROBE_LABEL#*@}"
if ! printf '%s' "$plain" | grep -qF "@${PROBE_LABEL_DOMAIN}"; then
    fail "output missing expected key_label domain '@${PROBE_LABEL_DOMAIN}' (PROBE_LABEL=$PROBE_LABEL)"
fi
if ! printf '%s' "$plain" | grep -qE '[⇡]1,234'; then
    fail "output missing expected input_tokens '⇡1,234'"
fi
if ! printf '%s' "$plain" | grep -qE '[⇣]458'; then
    fail "output missing expected output_tokens '⇣458'"
fi

# ---------------------------------------------------------------------------
# Negative probe: if stdin's session_id doesn't match, statusline should
# output nothing (the model-id fallback would also match, so we assert
# empty only when model is different too).
# ---------------------------------------------------------------------------
UNMATCHED_STDIN='{"session_id":"no-match","model":{"id":"some-other-model"}}'
UNMATCHED_OUT="$(printf '%s' "$UNMATCHED_STDIN" | "$AIKEY_BIN" statusline 2>/dev/null || true)"
if [ -n "$UNMATCHED_OUT" ]; then
    fail "expected empty output for unmatched session+model, got '${UNMATCHED_OUT}'"
fi

# ---------------------------------------------------------------------------
# Fallback probe: same session_id mismatch but matching model.id should
# still render a line via the model.id fallback path.
# ---------------------------------------------------------------------------
FALLBACK_STDIN="$(printf '{"session_id":"wrong-session","model":{"id":"%s"}}' "$PROBE_MODEL")"
FALLBACK_OUT="$(printf '%s' "$FALLBACK_STDIN" | "$AIKEY_BIN" statusline 2>/dev/null || true)"
fallback_plain="$(printf '%s' "$FALLBACK_OUT" | sed 's/\x1b\[[0-9;]*m//g')"
if ! printf '%s' "$fallback_plain" | grep -qF "@${PROBE_LABEL_DOMAIN}"; then
    fail "model.id fallback did not match: output='${FALLBACK_OUT}'"
fi

# ---------------------------------------------------------------------------
# last-active subcommand: scans WAL and prints newest session+model as
# "session_id: …", "model: …", "age: …" lines.  Invoked without stdin so
# the TTY-detect path doesn't trigger (we still want the command to run).
# ---------------------------------------------------------------------------
LAST_ACTIVE_OUT="$("$AIKEY_BIN" statusline last-active </dev/null 2>&1 || true)"
if ! printf '%s' "$LAST_ACTIVE_OUT" | grep -qE "^session_id:[[:space:]]+$PROBE_SESSION$"; then
    fail "last-active did not report session_id='$PROBE_SESSION': output='${LAST_ACTIVE_OUT}'"
fi
if ! printf '%s' "$LAST_ACTIVE_OUT" | grep -qE "^model:[[:space:]]+$PROBE_MODEL$"; then
    fail "last-active did not report model='$PROBE_MODEL': output='${LAST_ACTIVE_OUT}'"
fi
if ! printf '%s' "$LAST_ACTIVE_OUT" | grep -qE "^age:"; then
    fail "last-active missing age line: output='${LAST_ACTIVE_OUT}'"
fi

echo "probe PASSED — session_id matched, fallback matched, negative case returned empty, last-active reported newest event"

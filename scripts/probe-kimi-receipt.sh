#!/usr/bin/env bash
#
# probe-kimi-receipt.sh — end-to-end plumbing probe for the Kimi receipt
# feature (费用小票-Kimi集成).
#
# Verifies without a live Kimi session:
#   1. `aikey statusline render kimi` reads a Stop-hook stdin payload,
#      scans the WAL for matching {session_id, provider=kimi} events,
#      aggregates tokens, and writes a notification file with
#      targets=["shell"] (never "llm").
#   2. Watermark file is created at ~/.aikey/run/kimi-turns/<sid>.watermark
#      and advances after a successful render.
#   3. Second invocation with no new WAL entries is a no-op (at-least-once
#      replay semantics require watermark to prevent duplicate toasts).
#   4. Multi-event turn aggregation: N events with increasing wal_seq
#      collapse into ONE notification with summed tokens.
#   5. Negative: no WAL match → no notification, watermark stays put.
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
# Sandbox HOME so we never touch the user's real ~/.aikey or ~/.kimi.
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
export HOME="$SANDBOX"

WAL_DIR="$SANDBOX/.aikey/data/usage-wal"
TURNS_DIR="$SANDBOX/.aikey/run/kimi-turns"
mkdir -p "$WAL_DIR"

PROBE_SESSION="kimi-probe-$(date +%s)-$$"
PROBE_MODEL="kimi-k2.5"
PROBE_LABEL="aikey-kimi-probe@example.com"
PROBE_CWD="$SANDBOX/project"
mkdir -p "$PROBE_CWD"

# kimi-cli hashes cwd with md5 (see WorkDirMeta.sessions_dir in
# https://github.com/MoonshotAI/kimi-cli). We pre-compute that hash here so
# the assertion points at the right dir.
CWD_HASH="$(printf '%s' "$PROBE_CWD" | md5 -q 2>/dev/null \
    || printf '%s' "$PROBE_CWD" | md5sum | awk '{print $1}')"
SESSION_DIR="$SANDBOX/.kimi/sessions/$CWD_HASH/$PROBE_SESSION"
mkdir -p "$SESSION_DIR"

HOUR="$(date -u +%Y%m%d-%H)"
WAL_FILE="$WAL_DIR/usage-${HOUR}.jsonl"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

fail() {
    echo "probe FAILED: $1" >&2
    echo "---" >&2
    echo "wal_file:    $WAL_FILE" >&2
    echo "session_dir: $SESSION_DIR" >&2
    echo "turns_dir:   $TURNS_DIR" >&2
    if [ -f "$WAL_FILE" ]; then
        echo "wal contents:" >&2
        cat "$WAL_FILE" >&2
    fi
    if [ -d "$SESSION_DIR/notifications" ]; then
        echo "notifications tree:" >&2
        find "$SESSION_DIR/notifications" -type f -exec echo "  {}" \; -exec cat "{}" \; -exec echo >&2 \;
    fi
    exit 1
}

# ---------------------------------------------------------------------------
# WAL writer helper — appends one envelope line matching the proxy's shape.
# ---------------------------------------------------------------------------
write_wal_event() {
    local wal_path="$1" seq="$2" session="$3" input="$4" output="$5" event_id="$6"
    python3 - "$wal_path" "$NOW_ISO" "$session" "$PROBE_LABEL" "$PROBE_MODEL" \
        "$seq" "$input" "$output" "$event_id" <<'PY'
import json, sys
path, now, sid, label, model, seq, in_tok, out_tok, eid = sys.argv[1:]
entry = {
    "wal_seq": int(seq),
    "written_at": now,
    "schema_version": 1,
    "event_json": {
        "event_id": eid,
        "event_time": now,
        "session_id": sid,
        "key_label": label,
        "key_type": "apikey",
        "route_source": "apikey",
        "completion": "complete",
        "virtual_key_id": "apikey:kimi-probe",
        "provider_code": "kimi",
        "model": model,
        "input_tokens": int(in_tok),
        "output_tokens": int(out_tok),
        "total_tokens": int(in_tok) + int(out_tok),
        "stop_reason": "end_turn",
        "request_status": "success",
        "http_status_code": 200,
    },
}
with open(path, "a") as f:
    f.write(json.dumps(entry) + "\n")
PY
}

# ---------------------------------------------------------------------------
# Stop-hook stdin payload (Kimi 1.36 shape).
# ---------------------------------------------------------------------------
STOP_STDIN=$(printf '{"hook_event_name":"Stop","session_id":"%s","cwd":"%s","stop_hook_active":false}' \
    "$PROBE_SESSION" "$PROBE_CWD")

# ---------------------------------------------------------------------------
# Scenario 1: single turn, single WAL event.
# ---------------------------------------------------------------------------
write_wal_event "$WAL_FILE" 1 "$PROBE_SESSION" 8377 11 "ev-t1"

printf '%s' "$STOP_STDIN" | "$AIKEY_BIN" statusline render kimi >/dev/null 2>&1 \
    || fail "render kimi returned non-zero on scenario 1"

# Assert notification file exists with correct shape.
NOTIF_COUNT=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
[ "$NOTIF_COUNT" = "1" ] || fail "scenario 1: expected 1 notification dir, got $NOTIF_COUNT"

NOTIF_DIR=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 | head -n1)
EVENT_JSON="$NOTIF_DIR/event.json"
DELIVERY_JSON="$NOTIF_DIR/delivery.json"
[ -f "$EVENT_JSON" ] || fail "scenario 1: missing event.json at $EVENT_JSON"
[ -f "$DELIVERY_JSON" ] || fail "scenario 1: missing delivery.json at $DELIVERY_JSON"

# Critical invariant: targets MUST be ["shell"] only — never include "llm".
python3 - "$EVENT_JSON" <<'PY' || exit 1
import json, sys
with open(sys.argv[1]) as f:
    ev = json.load(f)
targets = ev.get("targets", [])
if targets != ["shell"]:
    print(f"event.json targets mismatch: got {targets!r}, want ['shell']", file=__import__('sys').stderr)
    sys.exit(1)
if ev.get("category") != "system": sys.exit(1)
if ev.get("type") != "receipt": sys.exit(1)
if ev.get("source_kind") != "aikey": sys.exit(1)
title = ev.get("title", "")
# render_line output after ANSI-strip should contain the input/output tokens.
if "8,377" not in title and "8.3K" not in title:
    print(f"event.json title missing input tokens: {title!r}", file=__import__('sys').stderr)
    sys.exit(1)
if "11" not in title:
    print(f"event.json title missing output tokens: {title!r}", file=__import__('sys').stderr)
    sys.exit(1)
PY

# Watermark should have advanced.
WM_FILE="$TURNS_DIR/$PROBE_SESSION.watermark"
[ -f "$WM_FILE" ] || fail "scenario 1: watermark file missing at $WM_FILE"
WM_CONTENT="$(cat "$WM_FILE")"
# Expect: "<wal_file_name>\t<seq>" — wal_file_name is the basename.
case "$WM_CONTENT" in
    "usage-${HOUR}.jsonl	1") : ;;
    *) fail "scenario 1: watermark content unexpected: '$WM_CONTENT'" ;;
esac

# ---------------------------------------------------------------------------
# Scenario 2: same stdin, no new WAL events → MUST be a no-op (idempotent
# retry / hook-fires-twice safety). Notification count unchanged.
# ---------------------------------------------------------------------------
printf '%s' "$STOP_STDIN" | "$AIKEY_BIN" statusline render kimi >/dev/null 2>&1 \
    || fail "render kimi returned non-zero on scenario 2 (replay)"

NOTIF_COUNT_2=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
[ "$NOTIF_COUNT_2" = "1" ] || \
    fail "scenario 2: expected 1 notification after replay (no new WAL), got $NOTIF_COUNT_2"

# ---------------------------------------------------------------------------
# Scenario 3: multi-event turn aggregation. Write 3 new WAL events with
# increasing wal_seq, invoke once → expect ONE new notification with summed
# tokens (aggregation proof).
# ---------------------------------------------------------------------------
# Snapshot dirs before scenario 3 so we can find the one added by this
# invocation. mtime-based sort is unreliable when everything runs within
# the same second (macOS stat has 1 s resolution).
BEFORE_SET=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 2>/dev/null | sort)

write_wal_event "$WAL_FILE" 2 "$PROBE_SESSION" 100 10 "ev-t2a"
write_wal_event "$WAL_FILE" 3 "$PROBE_SESSION" 200 20 "ev-t2b"
write_wal_event "$WAL_FILE" 4 "$PROBE_SESSION" 300 30 "ev-t2c"

printf '%s' "$STOP_STDIN" | "$AIKEY_BIN" statusline render kimi >/dev/null 2>&1 \
    || fail "render kimi returned non-zero on scenario 3"

NOTIF_COUNT_3=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
[ "$NOTIF_COUNT_3" = "2" ] || \
    fail "scenario 3: expected 2 notifications total (1 + 1 aggregated), got $NOTIF_COUNT_3"

# Identify the one new dir via set difference — immune to mtime aliasing.
AFTER_SET=$(find "$SESSION_DIR/notifications" -type d -mindepth 1 -maxdepth 1 2>/dev/null | sort)
NEWEST_NOTIF=$(comm -13 <(printf '%s\n' "$BEFORE_SET") <(printf '%s\n' "$AFTER_SET") | head -n1)
[ -n "$NEWEST_NOTIF" ] || fail "scenario 3: could not locate the newly-created notification dir"
NEW_EVENT_JSON="$NEWEST_NOTIF/event.json"
python3 - "$NEW_EVENT_JSON" <<'PY' || exit 1
import json, sys
with open(sys.argv[1]) as f:
    ev = json.load(f)
title = ev.get("title", "")
# Sum: 100+200+300 = 600 input, 10+20+30 = 60 output.
if "600" not in title:
    print(f"scenario 3: aggregated title missing summed input '600': {title!r}", file=sys.stderr)
    sys.exit(1)
if "60" not in title:
    print(f"scenario 3: aggregated title missing summed output '60': {title!r}", file=sys.stderr)
    sys.exit(1)
if ev["payload"].get("events_folded") != 3:
    print(f"scenario 3: events_folded mismatch: got {ev['payload'].get('events_folded')!r}, want 3", file=sys.stderr)
    sys.exit(1)
PY

# Watermark should now point at seq 4.
WM_CONTENT_3="$(cat "$WM_FILE")"
case "$WM_CONTENT_3" in
    "usage-${HOUR}.jsonl	4") : ;;
    *) fail "scenario 3: watermark should advance to seq 4, got '$WM_CONTENT_3'" ;;
esac

# ---------------------------------------------------------------------------
# Scenario 4: unrelated session_id → no notification, no watermark update.
# ---------------------------------------------------------------------------
OTHER_SESSION="kimi-probe-other-$$"
OTHER_CWD="$SANDBOX/other-project"
mkdir -p "$OTHER_CWD"
OTHER_CWD_HASH="$(printf '%s' "$OTHER_CWD" | md5 -q 2>/dev/null \
    || printf '%s' "$OTHER_CWD" | md5sum | awk '{print $1}')"
OTHER_SESSION_DIR="$SANDBOX/.kimi/sessions/$OTHER_CWD_HASH/$OTHER_SESSION"
mkdir -p "$OTHER_SESSION_DIR"

OTHER_STDIN=$(printf '{"hook_event_name":"Stop","session_id":"%s","cwd":"%s","stop_hook_active":false}' \
    "$OTHER_SESSION" "$OTHER_CWD")
printf '%s' "$OTHER_STDIN" | "$AIKEY_BIN" statusline render kimi >/dev/null 2>&1 \
    || fail "render kimi returned non-zero on scenario 4"

[ ! -d "$OTHER_SESSION_DIR/notifications" ] || {
    count=$(find "$OTHER_SESSION_DIR/notifications" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    [ "$count" = "0" ] || fail "scenario 4: expected 0 notifications for unrelated session, got $count"
}
OTHER_WM="$TURNS_DIR/$OTHER_SESSION.watermark"
[ ! -f "$OTHER_WM" ] || fail "scenario 4: watermark should NOT be created for no-match turn"

echo "probe PASSED — single-event render, replay no-op, 3-event aggregation, unrelated-session isolation all verified"

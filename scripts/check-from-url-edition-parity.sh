#!/usr/bin/env bash
# check-from-url-edition-parity.sh — T-EDN-1 / task 7.6.
#
# The requirement: the same `.well-known/aikey-provider.json`, run through
# `aikey add --from-url` on Personal / Trial / Production, must produce a
# credential configuration that is identical field for field. A capability
# that behaves differently in one edition is a bug (I-13), and the shape it
# takes in practice is not "the feature is missing" — it is "the same command
# quietly wrote a different config", which nobody notices until the customer
# in the edition nobody tested reports that routing goes somewhere else.
#
# 🔴 WHY THIS IS A STATIC FENCE AND NOT THREE TEST RUNS
#
# Three runs prove the three configurations that existed on the day someone
# ran them. This asserts the stronger thing: THE CODE ON THAT PATH CANNOT SEE
# WHICH EDITION IT IS IN, so there is no branch for a difference to come out
# of. Edition is a real concept in this CLI — `local_server_probe::Edition`,
# detected from which local server is installed — and five files consult it.
# None of them is on the from-url path, and this fence is what keeps that
# true.
#
# 🔴 It also states the thing the task text gets wrong. `Edition` has exactly
# two variants, Personal and Trial. "Production" is not a CLI edition at all:
# it is the self-hosted deployment of the platform, where the same binary runs
# with no local server present at all (detect_edition() returns None). So the
# matrix's third row is not a third code path — it is the SAME path with the
# detection returning nothing, which is precisely why "the path never asks" is
# the property worth guarding.
#
# Run with --self-test to prove it can go red.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/src"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

# The modules that implement `add --from-url`, from the flag to the write.
# 🔴 Keep this list honest: if the command grows a module, add it here. A
# module missing from this list is a module this fence does not protect.
PATH_MODULES=(
  "src/provider_selfdesc.rs"   # fetch, gate, parse, compare
  "src/main.rs"                # the add command itself
  "src/cli.rs"                 # flag definitions
)

scan() {
  local root=$1 fail=0 m hits
  for m in "${PATH_MODULES[@]}"; do
    [[ -f "$root/$m" ]] || { red "  missing module: $m"; fail=1; continue; }
    # `Edition` the type, `detect_edition` the accessor. Word-boundary so a
    # comment mentioning "editions" in prose does not trip it — a fence that
    # fires on the word in a sentence gets its matcher loosened, and a
    # loosened matcher stops catching the real thing.
    hits=$(grep -nE '\b(Edition|detect_edition)\b' "$root/$m" || true)
    if [[ -n "$hits" ]]; then
      red "  FAIL: $m consults the edition on the --from-url path:"
      sed 's/^/      /' <<<"$hits"
      red "        The same .well-known must yield the same credential in every"
      red "        edition (I-13, T-EDN-1). A branch here is where that stops"
      red "        being true, silently, for whichever edition nobody ran."
      fail=1
    fi
  done
  return $fail
}

self_test() {
  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  local passes=0 failures=0

  mkdir -p "$tmp/src"
  local m
  for m in "${PATH_MODULES[@]}"; do cp "$ROOT_DIR/$m" "$tmp/$m"; done

  if scan "$tmp" >/dev/null 2>&1; then
    passes=$((passes+1)); green "  ok: the real from-url path is edition-blind"
  else
    failures=$((failures+1)); red "  FAIL: the real path already consults the edition"
  fi

  # The mutation is the plausible one: a well-meaning "Trial gets a different
  # default" branch, which is exactly how I-13 gets broken.
  printf '\nfn drill(e: Edition) -> u8 { match e { Edition::Trial => 1, _ => 0 } }\n' \
    >> "$tmp/src/provider_selfdesc.rs"
  if scan "$tmp" >/dev/null 2>&1; then
    failures=$((failures+1)); red "  FAIL: an edition branch on the path was NOT detected"
  else
    passes=$((passes+1)); green "  ok: an edition branch on the path is caught"
  fi

  # And it must not fire on prose. `Edition` inside a comment is how a fence
  # like this gets called noisy and then loosened.
  cp "$ROOT_DIR/src/provider_selfdesc.rs" "$tmp/src/provider_selfdesc.rs"
  printf '\n// Note: identical across every edition, deliberately.\n' \
    >> "$tmp/src/provider_selfdesc.rs"
  if scan "$tmp" >/dev/null 2>&1; then
    passes=$((passes+1)); green "  ok: the word 'edition' in a comment does not trip it"
  else
    failures=$((failures+1)); red "  FAIL: tripped on prose — this matcher would get loosened"
  fi

  echo
  if [[ $failures -gt 0 ]]; then red "self-test FAIL — $passes passed, $failures failed"; return 1; fi
  green "self-test PASS — $passes/$passes"
}

case "${1:-}" in
  --self-test) self_test ;;
  "")
    echo "=== T-EDN-1: the --from-url path cannot see which edition it is in ==="
    if scan "$ROOT_DIR"; then
      green "  ok: no edition branching on the path (${#PATH_MODULES[@]} modules scanned)"
    else
      exit 1
    fi
    ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

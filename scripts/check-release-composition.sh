#!/usr/bin/env bash
# check-release-composition.sh — is the change actually IN the branch a
# release would package?
#
# Task 7.8, "离线包自证（若涉及 CLI 发版）". Hard rule 4 of the七阶段:
# the offline package must deploy successfully to the pre-release
# environment before GitHub accepts the artifact — "包先证明自己".
#
# 🔴 THAT PROOF IS ABOUT DEPLOYABILITY, NOT CONTENTS, AND THE DIFFERENCE IS
# THE WHOLE REASON THIS SCRIPT EXISTS.
#
# A package built from a branch that never received this change deploys
# perfectly. Every health check passes. §3.0's gate is satisfied, the
# artifact goes to GitHub, and the feature the release was cut for is not
# in the box. Nothing in the release pipeline notices, because nothing in
# it knows what the release was supposed to contain.
#
# Verified on 2026-08-11, and this is not hypothetical: `aikey add
# --from-url` (P4 of the public-trust-check-platform change) lives ONLY on
# `feat/public-trust-check-platform`. `git branch --contains` returns that
# branch and nothing else — not develop-v1.0.5, not develop-v1.0.4, not
# main. A release cut from the RC line today would self-prove a package
# with none of it.
#
# 🔴 AND A NAIVE GREP SAYS THE OPPOSITE. `git grep from_url develop-v1.0.5`
# returns a hit — `infer_provider_from_url`, an unrelated helper in the
# import parser. A substring check on this exact question reports the
# change as present when it is absent, which is worse than no check. So
# every symbol below is matched as the DECLARATION it is, not as text.
#
# Usage:
#   check-release-composition.sh [branch]    # default: $RELEASE_BRANCH or develop-v1.0.5
#   check-release-composition.sh --self-test

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"
BRANCH="${1:-${RELEASE_BRANCH:-develop-v1.0.5}}"
[ "$BRANCH" = "--self-test" ] && BRANCH="${RELEASE_BRANCH:-develop-v1.0.5}"

PASS=0; FAIL=0
ok()  { printf '\033[1;32mok  \033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

# Each row: <what it is>|<file>|<extended regex that matches the DECLARATION>
#
# 🔴 Anchored on declarations (a `mod` line, a struct field, a `use`), never
# on a bare identifier. The false positive this avoids is real and is named
# in the header.
REQUIRED='the --from-url CLI flag|src/cli.rs|^[[:space:]]*from_url:[[:space:]]*Option<String>,
the provider self-description module|src/lib.rs|^pub mod provider_selfdesc;
main wiring for the module|src/main.rs|^use .*::provider_selfdesc as selfdesc;
the module itself|src/provider_selfdesc.rs|^//!'

check_branch() { # <branch> → 0 when every required declaration is present
    local branch="$1" missing=0 row what file re
    if ! git -C "$REPO" rev-parse --verify --quiet "$branch" >/dev/null; then
        bad "no such branch: ${branch} — cannot judge composition against a ref that does not exist"
        return 1
    fi
    while IFS='|' read -r what file re; do
        [ -n "$what" ] || continue
        # 🔴 A HERESTRING, NOT A PIPE, and this cost two rounds to get right.
        # `git show … | grep -q` is wrong under `set -o pipefail`: grep -q
        # exits the instant it matches, the writer takes SIGPIPE, and
        # pipefail reports the PIPELINE as failed — so a match becomes a
        # miss. It only bites on large files, which is what makes it nasty:
        # lib.rs (40 lines) finished writing before grep exited and "passed",
        # while main.rs (8,624 lines) "failed" — three real declarations
        # reported missing from the branch that actually has them. Piping
        # from `printf` instead of `git` just moves which process gets the
        # signal. A herestring has no writer to kill.
        content="$(git -C "$REPO" show "${branch}:${file}" 2>/dev/null || true)"
        if grep -qE "$re" <<<"$content"; then
            ok "${branch} carries ${what} (${file})"
        else
            bad "${branch} is MISSING ${what} (${file})"
            missing=$((missing+1))
        fi
    done <<EOF
$REQUIRED
EOF
    [ "$missing" -eq 0 ]
}

echo "release-composition: judging '${BRANCH}' (the branch a release would build)"
echo

if check_branch "$BRANCH"; then
    :
else
    echo
    echo "🔴 The offline package built from '${BRANCH}' would DEPLOY FINE and"
    echo "   contain none of this change. §3.0's self-proof cannot catch that:"
    echo "   it proves the package installs, not that it holds what the release"
    echo "   was cut for."
    echo "   Fix: land the change on '${BRANCH}' before cutting the release, or"
    echo "   cut from the branch that has it. 🚫 Do not record 7.8 as done on a"
    echo "   package that does not contain the feature."
fi

# Where the change DOES live, so the message is actionable rather than just bad news.
echo
echo "branches containing the current HEAD:"
git -C "$REPO" branch --contains HEAD 2>/dev/null | sed 's/^/    /'

if [ "${1:-}" = "--self-test" ] || [ "${2:-}" = "--self-test" ]; then
    echo
    echo "self-test: the checks above must be able to fail, and must not fire on prose"

    # ㈠ The branch that HAS the change must pass. A fence that fails on the
    # correct branch too is a fence that says nothing, and it is the version
    # that gets deleted first.
    head_branch="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
    if check_branch "$head_branch" >/dev/null 2>&1; then
        ok "self-test ㈠: the feature branch (${head_branch}) satisfies every requirement"
    else
        bad "self-test ㈠: the feature branch does NOT satisfy the requirements — "\
"the required-symbol list is wrong, not the branch"
    fi

    # ㈡ THE FALSE POSITIVE. This is the one that matters: a substring check
    # for `from_url` finds `infer_provider_from_url` on the release branch
    # and reports the feature as present. The declaration-anchored check
    # must not.
    fp_src="$(git -C "$REPO" show "${BRANCH}:src/commands_internal/parse/grouping/cluster.rs" 2>/dev/null || true)"
    cli_src="$(git -C "$REPO" show "${BRANCH}:src/cli.rs" 2>/dev/null || true)"
    if grep -q "infer_provider_from_url" <<<"$fp_src"; then
        if grep -qE '^[[:space:]]*from_url:[[:space:]]*Option<String>,' <<<"$cli_src"; then
            bad "self-test ㈡: the declaration matcher fired on ${BRANCH}, which has only "\
"the unrelated infer_provider_from_url"
        else
            ok "self-test ㈡: infer_provider_from_url does NOT satisfy the --from-url check"
        fi
    else
        # 🔴 Loud, not silent: this self-test is the reason the matcher is
        # shaped the way it is, and if its subject moves the reasoning has to
        # be re-derived rather than quietly dropped.
        printf '\033[1;33m[ SKIP ]\033[0m %s\n' \
            "self-test ㈡: infer_provider_from_url is no longer on ${BRANCH} — "
        printf '\033[1;33m       \033[0m %s\n' \
            "re-derive the false-positive case before trusting this matcher."
    fi

    # ㈢ A missing declaration must be caught. Judge an ancestor that predates
    # the whole change: it must fail, or the check is not checking.
    old="$(git -C "$REPO" rev-list --max-parents=0 HEAD 2>/dev/null | head -1)"
    if [ -n "$old" ] && check_branch "$old" >/dev/null 2>&1; then
        bad "self-test ㈢: the initial commit satisfied the requirements — the check is vacuous"
    else
        ok "self-test ㈢: a ref without the change is correctly rejected"
    fi
fi

echo
echo "release-composition: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ] || exit 1

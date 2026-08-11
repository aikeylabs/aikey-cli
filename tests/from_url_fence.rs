//! Mechanical fences for `aikey add --from-url` (P4, tasks 4.1 / 4.6 / 4.8).
//!
//! Each one guards a property that a behavioural test cannot see, because
//! breaking it makes the command WORK — just not the way we promised.

use std::fs;

/// The `Commands::Add` arm of the dispatch, as source text.
fn add_arm() -> String {
    let src = fs::read_to_string("src/main.rs").expect("read src/main.rs");
    let start = src
        .find("Commands::Add {")
        .expect("the Add arm is gone; these fences no longer guard anything");
    // The next top-level `Commands::` arm ends it. Search from past the
    // opening so the match itself is not the terminator.
    let rest = &src[start + 16..];
    let end = rest
        .find("\n        Commands::")
        .map(|i| start + 16 + i)
        .unwrap_or(src.len());
    src[start..end].to_string()
}

// ────────────────────────────────────────────────────────── task 4.1

#[test]
fn from_url_writes_through_the_one_import_path() {
    // 🔴 TASK 4.1: "reuse the existing three-axis core; do NOT open a new
    // import path."
    //
    // A second writer is the tempting shape here — `--from-url` knows more
    // about what it is storing than the interactive flow does, so a dedicated
    // insert reads like a simplification. What it actually buys is a row that
    // skipped alias validation, canonical provider normalisation, and the
    // supported_providers / provider_code / base_url metadata the proxy routes
    // on. Nothing errors; the credential simply behaves differently from every
    // other credential, and only under this one flag.
    let arm = add_arm();
    // 🔴 The CALL form, not the bare name: this arm mentions the helper twice
    // in prose explaining why it is the only writer. A fence that counts prose
    // fails on a comment edit, and a fence that fails for the wrong reason is
    // one the next person deletes.
    let writes = arm.matches("apply_add_core_on_conn(").count();
    assert_eq!(
        writes, 1,
        "the Add arm calls apply_add_core_on_conn {writes} times; there must be \
         exactly one write path (task 4.1). A second one is a row that skipped \
         alias validation and provider normalisation."
    );

    for banned in ["INSERT INTO entries", "storage::insert_entry"] {
        assert!(
            !arm.contains(banned),
            "the Add arm writes the vault directly ({banned}). Every caller — \
             including `_internal vault-op` — goes through \
             commands_account::apply_add_core_on_conn."
        );
    }
}

// ────────────────────────────────────────────────────────── task 4.6

#[test]
fn what_gets_written_comes_from_the_measurement_and_not_the_declaration() {
    // 🔴 TASK 4.6. The declaration is a pre-fill; the probe decides. If the
    // providers handed to the write came from `declared_protocols`, a relay
    // could name a protocol it does not serve and we would store a credential
    // that cannot route — the exact failure the three-axis linkage already
    // shipped once (D-3), and one that surfaces days later as "my key does not
    // work" rather than at the moment it was created.
    let arm = add_arm();
    let write_at = arm
        .rfind("apply_add_core_on_conn")
        .expect("checked by the fence above");
    let narrowing = arm
        .find("measured.protocols")
        .expect("the from-url path no longer narrows providers to what answered (task 4.6)");
    assert!(
        narrowing < write_at,
        "providers are written before the measurement narrows them"
    );

    // And the declared list must not be what reaches the writer.
    let tail = &arm[write_at..];
    assert!(
        !tail.contains("declared_protocols"),
        "the declared protocol list reaches the vault write. Only what answered \
         may be stored (task 4.6)."
    );
}

#[test]
fn the_from_url_path_probes_and_cannot_be_skipped() {
    // 🔴 TASK 4.4. The ordinary probe is TTY-gated because it is a
    // convenience. Here it is the only reason the flag is safe: everything
    // being written was proposed by the operator of the endpoint the key is
    // about to be sent to. A `--from-url` that skipped the probe in --json or
    // in a pipe would be a scripted path that trusts a stranger's file.
    let arm = add_arm();
    let block = arm
        .split("Step 4b")
        .nth(1)
        .expect("the from-url measurement step (Step 4b) is gone");
    let block = block.split("Step 5").next().unwrap_or(block);
    assert!(
        block.contains("run_connectivity_suite"),
        "the from-url path no longer runs the connectivity suite"
    );
    assert!(
        !block.contains("is_terminal()"),
        "the from-url probe is gated on a TTY. It must run in --json and in a \
         pipe too — that is the only thing standing between this flag and \
         trusting a third party's file (task 4.4)."
    );
}

// ────────────────────────────────────────────────────────── task 4.8

#[test]
fn from_url_behaves_the_same_on_every_edition() {
    // 🔴 TASK 4.8: Personal / Trial / Production parity — "existing in only
    // one edition is a bug".
    //
    // Asserted as the absence of an edition branch rather than by running the
    // command three times, because the three editions differ by which SERVER
    // is installed beside the CLI, and a test harness cannot conjure a
    // Production install. What it CAN establish is that this code path never
    // asks which edition it is on, which makes the three answers identical by
    // construction.
    let arm = add_arm();
    for banned in ["Edition::", "detect_edition", "local_server_probe::Edition"] {
        assert!(
            !arm.contains(banned),
            "the Add arm branches on edition ({banned}). `--from-url` must behave \
             identically on Personal, Trial and Production — a flag that exists \
             in one edition is a bug (task 4.8), and the enterprise edition is \
             precisely the one whose relays this flag is for."
        );
    }

    let selfdesc = fs::read_to_string("src/provider_selfdesc.rs").expect("read module");
    for banned in ["Edition::", "detect_edition"] {
        assert!(
            !selfdesc.contains(banned),
            "provider_selfdesc branches on edition ({banned})"
        );
    }
}

// ────────────────────────────────────────────────────────── task 4.2c

#[test]
fn the_reason_the_two_gates_differ_is_written_next_to_the_gate() {
    // 🔴 TASK 4.2c. The next person to read this file will notice that the
    // check site refuses what this allows and will "fix" the inconsistency.
    // The explanation has to be where they are standing, not in a document
    // they have no reason to open.
    let src = fs::read_to_string("src/provider_selfdesc.rs").expect("read module");
    for required in [
        "R-3b",
        "dgcheck",
        "whose machine is dialling",
        "T-EDN-3b",
    ] {
        assert!(
            src.contains(required),
            "the gate no longer explains why it is weaker than the check site's \
             (missing: {required:?}). Task 4.2c: without it, somebody tightens \
             this for consistency and deletes the enterprise onboarding path."
        );
    }
}

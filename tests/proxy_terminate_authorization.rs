//! Source invariant: terminating a live aikey-proxy is opt-in, and the
//! ONLY command that opts in is `aikey proxy restart`.
//!
//! Why a source-level gate rather than a behavioral one: reaching the
//! `Unresponsive` branch of `start_proxy_locked_inner` for real requires a
//! live, ownership-verified aikey-proxy process that binds the configured
//! port and refuses /health — not something a unit test can conjure
//! honestly. What CAN regress cheaply, though, is a new call site quietly
//! passing `terminate_unresponsive: true` to get past a refusal, which is
//! exactly how the implicit kill reached the wrapper hot path in the first
//! place. This gate is aimed at that specific regression.
//!
//! Background (2026-08-04, DESKTOP-S7JJK1B): `ensure-running` — which runs
//! on every `claude` / `codex` / `kimi` launch and from any keep-alive
//! timer — routed through the start path, which SIGTERM/SIGKILLed an
//! incumbent classified `Unresponsive`. A busy proxy was killed mid-request
//! by a routine liveness check, on a loop, with no human in it.

const LIFECYCLE_SRC: &str = include_str!("../src/proxy_lifecycle.rs");
const COMMANDS_SRC: &str = include_str!("../src/commands_proxy.rs");

/// The authorization is granted in exactly one place, and that place is
/// `restart_proxy`.
#[test]
fn only_restart_proxy_grants_termination_authority() {
    let grants: Vec<usize> = LIFECYCLE_SRC
        .match_indices("terminate_unresponsive = true")
        .map(|(i, _)| i)
        .collect();

    assert_eq!(
        grants.len(),
        1,
        "expected exactly one place to grant termination authority, found {}. \
         Killing a live process must stay tied to the one command that carries \
         the user's explicit intent (`aikey proxy restart`).",
        grants.len()
    );

    let restart_fn = LIFECYCLE_SRC
        .find("pub fn restart_proxy(")
        .expect("restart_proxy must exist — this gate is anchored to it");

    assert!(
        grants[0] > restart_fn,
        "termination authority is granted before restart_proxy is even defined"
    );

    // Nothing that looks like another function boundary may sit between
    // `restart_proxy`'s signature and the grant — i.e. the grant is inside
    // restart_proxy, not in some later function.
    let between = &LIFECYCLE_SRC[restart_fn + "pub fn restart_proxy(".len()..grants[0]];
    assert!(
        !between.contains("\nfn ") && !between.contains("\npub fn "),
        "the `terminate_unresponsive = true` grant is no longer inside \
         restart_proxy — another function now claims kill authority"
    );
}

/// No CLI-side caller may construct `StartOptions` pre-authorized to kill.
/// `build_start_options` feeds `start`, `ensure-running`, the wrapper
/// preflight and `restart` alike; the authorization is added by
/// `restart_proxy` afterwards, never baked into the options.
#[test]
fn no_cli_call_site_constructs_a_pre_authorized_start() {
    let opted_in = COMMANDS_SRC.matches("terminate_unresponsive: true").count();
    assert_eq!(
        opted_in, 0,
        "a caller in commands_proxy.rs constructs StartOptions with \
         terminate_unresponsive: true. Start must never be the thing that \
         kills a live proxy — if a command genuinely needs to replace one, \
         route it through `restart_proxy`."
    );

    assert!(
        COMMANDS_SRC.contains("terminate_unresponsive: false"),
        "build_start_options must set terminate_unresponsive explicitly, so \
         the default-deny is visible at the construction site rather than \
         inherited silently"
    );
}

/// The refusal must send the user somewhere. An error that says "no"
/// without naming the command that says "yes" just gets worked around.
#[test]
fn the_refusal_names_the_command_that_can_replace_the_proxy() {
    let refusal_arm = LIFECYCLE_SRC
        .find("StartError::UnresponsiveRefused { pid, port } => write!")
        .expect("UnresponsiveRefused must have a Display arm");
    let arm_text = &LIFECYCLE_SRC[refusal_arm..refusal_arm + 600];

    assert!(
        arm_text.contains("aikey proxy restart"),
        "the refusal message must name `aikey proxy restart` as the way forward"
    );
}

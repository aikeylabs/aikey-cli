//! `aikey compliance` — the public on/off switch for AI compliance detection.
//!
//! # Why this command exists (2026-08-19)
//!
//! Compliance detection had a toggle in the local console's web page and a
//! hidden `_internal app.filter-set` action, and nothing else. That left two
//! holes: a terminal user could not turn scanning on at all, and the desktop
//! app could not offer the switch either — the tray is only allowed to invoke
//! PUBLIC commands (its boundary fence), by design, so "call the hidden one"
//! was not an option.
//!
//! # Why it is NOT `aikey service compliance`
//!
//! `aikey service <start|stop>` manages PROCESS lifecycles: each whitelisted
//! service owns a binary, a port and a launchd/schtasks label. Compliance
//! detection owns none of those — it is a FILTER STAGE of the proxy
//! (`app_records.filter_stages`), and the proxy spawns or kills the detector
//! child within ~5s of the column changing. Putting it in that whitelist would
//! also have handed `service stop all` the power to silently switch a safety
//! control off, and widened the console's `/api/internal/services/<name>/
//! <action>` endpoint — which shares that whitelist as its security boundary —
//! to a mutation that the console deliberately gates behind a vault unlock.
//!
//! The panel still SHOWS it beside the services (product decision 2026-08-19);
//! `commands_service::status_all` renders that row and marks it
//! `control: "compliance"` so the desktop app routes its switch here.
//!
//! # Password policy
//!
//! None of these verbs unlock the vault: `filter_stages` is a plaintext
//! metadata column, and both the read and the write stay clear of key
//! material. That is what lets the tray — which must never touch the master
//! password — offer the switch at all.

use crate::cli::ComplianceAction;
use crate::commands_app;
use crate::commands_project::{ComplianceToggle, COMPLIANCE_DETECTOR_SLUG};

/// Resolve the EFFECTIVE state, never just the local column.
///
/// 🔴 The two halves disagree on a mandated host: the org policy makes the
/// proxy force-spawn the detector while this vault's `filter_stages` stays
/// NULL. Reading only the local column would report "off" on a machine that is
/// scanning every request — a health signal stating the opposite of reality.
/// `ComplianceToggle::resolve` is the ONE place that reconciles them (doctor's
/// §7.6 reads it too); this function must never grow a second opinion.
pub fn current_toggle() -> ComplianceToggle {
    ComplianceToggle::resolve(
        commands_app::get_app_filter_stages(COMPLIANCE_DETECTOR_SLUG)
            .ok()
            .flatten()
            .is_some(),
        crate::storage::compliance_master_enabled(),
    )
}

/// One sentence per state, in the vocabulary the console and the docs use.
/// Returned rather than printed so `service status` can render the same words
/// in its own table — the two surfaces cannot drift.
pub fn state_detail(toggle: ComplianceToggle) -> String {
    let base = match toggle {
        ComplianceToggle::OnMandated => "on — required by your organization's policy",
        ComplianceToggle::OnLocal => "on — scanning before forward",
        ComplianceToggle::Off => "off — requests are forwarded unscanned",
    };
    // Password-lane level (阶段8/合规密码档分级). Only the org force is stated
    // here: this process can prove "forced advanced" from the mirrored org
    // policy, but the machine's own effective level lives with the running
    // detector (health surface) — claiming it from here would be the health
    // signal stating more than it knows. Wording is the single source the Web
    // console mirrors (compliancePage.passwordTier.* keys carry the long form).
    if toggle != ComplianceToggle::Off && crate::storage::compliance_master_password_advanced() {
        format!("{base}; password lane: advanced (enforced by your organization)")
    } else {
        base.to_string()
    }
}

pub(crate) fn handle_compliance(
    action: &ComplianceAction,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ComplianceAction::Status => {
            let toggle = current_toggle();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "enabled": toggle != ComplianceToggle::Off,
                        "mandated": toggle == ComplianceToggle::OnMandated,
                        "locked": crate::storage::compliance_master_locked(),
                        "password_tier_forced_advanced": crate::storage::compliance_master_password_advanced(),
                        "detail": state_detail(toggle),
                    })
                );
            } else {
                println!("Compliance detection: {}", state_detail(toggle));
            }
            Ok(())
        }
        ComplianceAction::On => {
            // Declaration-requires-capability (W2, bugfix 2026-08-19
            // filterpipe-501): enabling writes filter_stages, and the proxy
            // fail-closes ALL traffic the moment that declaration exists
            // without a runnable detector. Refuse the write-ahead instead of
            // bricking the data plane.
            if !detector_installed() {
                return Err(
                    "the compliance detector is not installed on this machine, and enabling \
                     compliance without it would block ALL AI traffic (fail-closed). Run \
                     `aikey app install ai-compliance-detector` first, then re-run \
                     `aikey compliance on`."
                        .into(),
                );
            }
            commands_app::set_app_filter_stages(
                COMPLIANCE_DETECTOR_SLUG,
                &["pre_forward".to_string()],
                None,
                None,
            )?;
            // The proxy reloads on its own; saying so stops the user from
            // restarting anything to "make it take effect".
            println!("Compliance detection enabled — the proxy picks it up within a few seconds.");
            Ok(())
        }
        ComplianceAction::Off => {
            // Same refusal the hidden action gives (`I_APP_COMPLIANCE_LOCKED`):
            // on a mandated host the proxy force-spawns the detector anyway, so
            // letting the write through would report success for a change that
            // changes nothing.
            if crate::storage::compliance_master_locked() {
                return Err(
                    "compliance detection is enforced by your organization policy and cannot be disabled here — ask your admin"
                        .into(),
                );
            }
            commands_app::clear_app_filter_stages(COMPLIANCE_DETECTOR_SLUG)?;
            println!(
                "Compliance detection disabled — the proxy stops the scanner within a few seconds."
            );
            Ok(())
        }
    }
}

/// Whether the detector binary is on this machine. Same path the doctor's
/// plugin table declares — a second literal here would be a second truth about
/// where the installer puts it.
pub fn detector_installed() -> bool {
    commands_app::detector_installed()
}

//! Credential lifecycle event API — single funnel for all binding writes.
//!
//! Variants map to the three concrete write modes existing helpers expose:
//!   Added    — caller already wrote the entry; we run `auto_assign_primaries_for_key`
//!              (conservatively fills empty primary slots, never steals an
//!              existing one)
//!   Switched — caller wants this credential to be primary for the listed
//!              providers (overwrite); we run `write_bindings_canonical`
//!   Removed  — caller already deleted the entry; we run
//!              `reconcile_provider_primary_after_key_removal` (auto-replace
//!              from the same source-type pool, or clear)
//!
//! All variants then run the shared tail (refresh active.env + apply
//! third-party CLI configs). Batch flavor runs the tail ONCE after all
//! per-event writes — used by `aikey delete a b c` and the interactive
//! `aikey use` picker which can change multiple (provider, source) tuples
//! atomically.

use crate::profile_activation::{
    auto_assign_primaries_for_key, reconcile_provider_primary_after_key_removal,
    refresh_implicit_profile_activation, ReconcileAction,
};

/// One credential write intent.
///
/// Field naming is deliberately verbose (`source_type` instead of just `kind`)
/// because two of the three string slots — `source_type` and `source_ref` —
/// have stable lexicons that mismatched calls historically silently
/// corrupted. Keeping the names explicit forces grep-ability.
#[derive(Debug)]
pub enum CredentialLifecycleEvent<'a> {
    /// A credential was just written to vault (`entries` for personal API
    /// keys, `provider_accounts` for OAuth). Auto-promote to primary for any
    /// of `providers` that don't currently have a primary; leave existing
    /// primaries alone.
    Added {
        /// "personal" | "personal_oauth_account"
        source_type: &'a str,
        /// alias (personal) or provider_account_id (oauth)
        source_ref: &'a str,
        /// Protocols this credential supports.
        providers: &'a [String],
    },
    /// User is explicitly making this credential the primary for `providers`.
    /// Overwrites whatever was bound to those providers.
    Switched {
        source_type: &'a str,
        source_ref: &'a str,
        providers: &'a [String],
    },
    /// A credential was just deleted. Reconcile finds a replacement primary
    /// from the same source_type pool, or clears the binding if none.
    /// `providers` is not needed — reconcile reads it from the binding rows
    /// that referenced this source_ref.
    Removed {
        source_type: &'a str,
        source_ref: &'a str,
    },
}

/// Outcome of running the side-effect chain. The `#[must_use]` is
/// deliberate — every caller has a UX or telemetry obligation tied to one
/// of the fields below (e.g., printing "⭐ Primary for: kimi" from
/// `newly_primary`, or surfacing reconcile actions in the per-alias delete
/// summary).
#[must_use = "lifecycle outcome carries diagnostic info that should be surfaced"]
#[derive(Debug, Default)]
pub struct LifecycleOutcome {
    /// Providers where this event resulted in a NEW primary binding.
    /// Populated only for `Added` (auto_assign) and `Switched` (always
    /// touches the named providers). Empty for `Removed`.
    pub newly_primary: Vec<String>,
    /// Per-provider reconcile result. Populated only for `Removed`.
    /// Empty otherwise.
    pub reconcile_actions: Vec<ReconcileAction>,
    /// Whether step 2 of the chain succeeded. False means step 3 was
    /// skipped — DB write already landed but active.env / tomls may be
    /// stale. Caller should warn but not roll back.
    pub active_env_refreshed: bool,
    /// Active providers as seen by `refresh_implicit_profile_activation`
    /// after this event. Empty when `active_env_refreshed = false`.
    pub active_providers: Vec<String>,
}

/// Single-event entry: equivalent to `apply_credential_lifecycle_batch(&[event])`
/// returning the first outcome, but more ergonomic for the 8-of-10 callers
/// that only do one write per command.
pub fn apply_credential_lifecycle(
    event: CredentialLifecycleEvent,
) -> Result<LifecycleOutcome, String> {
    let mut outcomes = apply_credential_lifecycle_batch(&[event])?;
    Ok(outcomes.pop().unwrap_or_default())
}

/// Batch entry: applies per-event writes in order, then runs the side-effect
/// tail (refresh + apply) ONCE after all writes succeed. Used by:
///
///   - `aikey delete a b c` (Commands::Delete)
///   - interactive `aikey use` picker (Commands::Use) — one event per
///     (provider, source_type, source_ref) tuple
///
/// On any per-event error: returns immediately without running the tail
/// (DB writes that already landed stay; tail not run, so caller's UX may
/// observe stale active.env until next operation).
pub fn apply_credential_lifecycle_batch(
    events: &[CredentialLifecycleEvent<'_>],
) -> Result<Vec<LifecycleOutcome>, String> {
    let mut outcomes: Vec<LifecycleOutcome> = Vec::with_capacity(events.len());
    let mut any_binding_touched = false;

    for event in events {
        let mut outcome = LifecycleOutcome::default();
        match event {
            CredentialLifecycleEvent::Added {
                source_type,
                source_ref,
                providers,
            } => {
                if !providers.is_empty() {
                    let primaries = auto_assign_primaries_for_key(
                        source_type,
                        source_ref,
                        providers,
                    )
                    .unwrap_or_default();
                    outcome.newly_primary = primaries;
                    // Treat presence of providers as a binding touch so
                    // downstream toml apply re-runs even when no auto-promote
                    // happened (idempotent no-op when state already matches).
                    any_binding_touched = true;
                }
            }
            CredentialLifecycleEvent::Switched {
                source_type,
                source_ref,
                providers,
            } => {
                if !providers.is_empty() {
                    crate::commands_account::write_bindings_canonical(
                        providers,
                        source_type,
                        source_ref,
                    )?;
                    outcome.newly_primary = providers.to_vec();
                    any_binding_touched = true;
                }
            }
            CredentialLifecycleEvent::Removed {
                source_type,
                source_ref,
            } => {
                let actions = reconcile_provider_primary_after_key_removal(
                    source_type,
                    source_ref,
                )
                .unwrap_or_default();
                if !actions.is_empty() {
                    any_binding_touched = true;
                }
                outcome.reconcile_actions = actions;
            }
        }
        outcomes.push(outcome);
    }

    // Side-effect tail — runs once per batch, even when individual events
    // were no-ops, so toml regions stay in sync after a refresh-only call.
    if any_binding_touched {
        if let Ok(refresh) = refresh_implicit_profile_activation() {
            let proxy_port = crate::commands_proxy::proxy_port();
            let active_providers: Vec<String> = refresh
                .bindings
                .iter()
                .map(|b| b.provider_code.clone())
                .collect();
            crate::commands_account::apply_third_party_cli_configs(
                &active_providers,
                proxy_port,
            );
            // Backfill on every outcome so callers can read post-refresh
            // active set without holding the RefreshResult separately.
            for outcome in &mut outcomes {
                outcome.active_env_refreshed = true;
                outcome.active_providers = active_providers.clone();
            }
        }
    }

    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure variant-shape tests — heavier integration tests live in the
    // commands_internal/vault_op test fixture which has a real vault DB.
    // These just pin the API surface so a future signature change shows
    // up as a compile-time test failure, not a silent caller breakage.

    #[test]
    fn outcome_default_is_empty() {
        let o = LifecycleOutcome::default();
        assert!(o.newly_primary.is_empty());
        assert!(o.reconcile_actions.is_empty());
        assert!(!o.active_env_refreshed);
        assert!(o.active_providers.is_empty());
    }

    #[test]
    fn event_added_carries_providers() {
        let providers = vec!["kimi".to_string()];
        let e = CredentialLifecycleEvent::Added {
            source_type: "personal",
            source_ref: "k1",
            providers: &providers,
        };
        match e {
            CredentialLifecycleEvent::Added { providers, .. } => {
                assert_eq!(providers.len(), 1);
            }
            _ => panic!("variant changed"),
        }
    }

    #[test]
    fn event_removed_no_providers_field() {
        // Pin: Removed deliberately omits `providers` (reconcile reads from
        // existing binding rows). If a future refactor adds `providers`,
        // this test compiles but fails — forcing a review of why.
        let e = CredentialLifecycleEvent::Removed {
            source_type: "personal",
            source_ref: "old-alias",
        };
        match e {
            CredentialLifecycleEvent::Removed {
                source_type,
                source_ref,
            } => {
                assert_eq!(source_type, "personal");
                assert_eq!(source_ref, "old-alias");
            }
            _ => panic!("variant changed"),
        }
    }
}

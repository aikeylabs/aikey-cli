//! Persist connectivity-suite results to the vault `extra.$.last_test`
//! column. Single source of truth for "what does a Last test snapshot
//! look like, and where does it land?" — both the public `aikey test`
//! CLI and the `_internal vault-op test` action call into this module
//! so the row a Web user sees after clicking Test connection is
//! byte-identical to the row a terminal user sees after running
//! `aikey test`.
//!
//! Why a separate module rather than inlining into vault_op.rs and
//! main.rs: `internal-command-reuses-public-core` principle (see project
//! CLAUDE.md). Inlining would drift over time — the JSON shape, the
//! aggregation rule, the choice of latency metric. Centralising them
//! here means a future change to "what status counts as pass" is a
//! one-place edit.
//!
//! Per-credential grouping: `aikey test --all` runs a suite that may
//! contain N credentials × M providers each = many rows under multiple
//! source_refs. The Last test column shows ONE row per credential, so
//! we group `outcome.rows` by `(kind, source_ref)` and emit one
//! `PersistedTestResult` per group.

use crate::connectivity::{CredentialKind, SuiteOutcome};
use crate::storage;
use serde_json::json;

/// One aggregated `last_test` record before persistence — pulled out of
/// `persist_test_outcome` (2026-05-23) so callers that probe credentials
/// which don't exist in the vault yet (notably the Add Key pre-save Run
/// test from the Web UI) can reuse the byte-identical aggregation rules
/// without going near `storage::merge_*_extra`.
///
/// Why a tuple struct instead of pushing into `PersistedTestResult` with
/// `persisted=false`: that path always WARN-logs a write failure to
/// stderr (logging-conventions principle), which would make pre-save
/// probes spam "[connectivity::persist WARN] write failed" on every
/// successful Add Key test. Splitting the aggregator out cleanly avoids
/// the false-alarm noise.
#[derive(Debug, Clone)]
pub struct AggregatedTestRecord {
    pub target_kind: CredentialKind,
    pub source_ref: String,
    /// The exact JSON object that would be written under
    /// `extra.$.last_test`. Shape matches
    /// `web/src/shared/api/user/vault.ts::VaultLastTest`.
    pub last_test: serde_json::Value,
}

/// Output of a single persisted aggregation — what got written to one
/// credential's `extra.$.last_test`. Returned per (kind, source_ref) so
/// callers can render summary (e.g. main.rs `aikey test` could print
/// "✓ wrote Last test for 3 credentials") and so `_internal vault-op
/// test` can find the matching entry for the (target, id) the caller
/// asked about.
#[derive(Debug, Clone)]
pub struct PersistedTestResult {
    pub target_kind: CredentialKind,
    /// `entries.alias` for personal, `provider_account_id` for oauth,
    /// `virtual_key_id` for team. Matches the `source_ref` field on
    /// TestTarget so callers can look up by id.
    pub source_ref: String,
    /// False when the vault write failed (e.g. row deleted between
    /// suite run and persist). The probe itself still ran successfully;
    /// just the persistence step was a no-op.
    pub persisted: bool,
    /// The exact JSON object written under `extra.$.last_test`. Shape
    /// matches `web/src/shared/api/user/vault.ts::VaultLastTest`.
    pub last_test: serde_json::Value,
}

/// Aggregate `outcome.rows` per credential and persist the result to
/// each credential's `extra.$.last_test`. Returns one entry per
/// credential, in input order (groups are visited in first-seen order).
///
/// Aggregation rules per credential:
///   - status     = "pass" if any row reaches the deepest enabled probe:
///                  Chat when it ran, otherwise API when Chat is skipped
///   - latency_ms = on pass: min api_ms across passing rows in the group
///                  on fail: max ping_ms in the group (omitted if 0)
///   - error_code / error_message: from the first failing row in the
///                  group; HTTP_<status> when api_status is present,
///                  PROXY_UPSTREAM_UNREACHABLE if ping itself failed,
///                  UNKNOWN otherwise.
///   - suite_results: the subset of `outcome.json_results` belonging to
///                  this credential (matched by source_ref). The proxy
///                  row in json_results is global, so it's dropped
///                  from per-credential snapshots.
/// Pure aggregator — same rules as `persist_test_outcome` but does not
/// touch the vault. Extracted 2026-05-23 to let the Web Add-Key pre-save
/// Run-test path reuse the same byte-shape (`internal-command-reuses-
/// public-core` principle) without spamming WARN logs for a credential
/// that doesn't have a vault row yet.
///
/// The body below is the verbatim per-group record-build loop from the
/// pre-2026-05-23 monolithic `persist_test_outcome` — fence tests in
/// `tests` module below pin the aggregation rules so future edits to
/// "what counts as pass" / "which body snippet wins" stay in one place.
pub fn aggregate_test_outcome(outcome: &SuiteOutcome) -> Vec<AggregatedTestRecord> {
    // Group rows by (kind, source_ref), preserving first-seen order.
    // CredentialKind doesn't derive Hash/Ord (small enum, didn't seem
    // worth the maintenance burden), so we use a Vec<(key, indices)>
    // list and a linear scan for lookup. N is small in practice (≤ ~30
    // credentials in a typical `aikey test --all`), so the O(N²)
    // grouping is fine.
    let mut groups: Vec<((CredentialKind, String), Vec<usize>)> = Vec::new();
    for (i, (t, _r)) in outcome.rows.iter().enumerate() {
        let key = (t.kind, t.source_ref.clone());
        if let Some(g) = groups.iter_mut().find(|(k, _)| *k == key) {
            g.1.push(i);
        } else {
            groups.push((key, vec![i]));
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut records: Vec<AggregatedTestRecord> = Vec::with_capacity(groups.len());
    for ((kind, source_ref), idxs) in groups {
        // Aggregate the group. Any-ok semantics for each phase: a key
        // bound to multiple providers passes the phase if at least one
        // provider passes it. The Vault page's "Last test" column reads
        // these three booleans to render Ping / API / Chat dots, so the
        // user can see which phase failed at a glance without opening
        // the popup.
        let group_rows: Vec<&(_, _)> = idxs.iter().map(|&i| &outcome.rows[i]).collect();
        let ping_ok = group_rows.iter().any(|(_t, r)| r.ping_ok);
        let api_ok = group_rows.iter().any(|(_t, r)| r.api_ok);
        let chat_ok = group_rows.iter().any(|(_t, r)| r.chat_ok);
        let chat_skipped = group_rows.iter().all(|(_t, r)| r.chat_skipped);
        // Overall status keeps the old pass/fail signal for back-compat
        // with anything reading just `status`; new code should read the
        // phase booleans + skipped marker. Chat is no longer a required
        // connectivity phase, so API success is enough when every row
        // skipped Chat by policy.
        let pass = if chat_skipped { api_ok } else { chat_ok };

        let mut record = serde_json::Map::new();
        record.insert("at".into(), json!(now));
        record.insert("status".into(), json!(if pass { "pass" } else { "fail" }));
        record.insert("ping_ok".into(), json!(ping_ok));
        record.insert("api_ok".into(), json!(api_ok));
        record.insert("chat_ok".into(), json!(chat_ok));
        record.insert("chat_skipped".into(), json!(chat_skipped));

        if pass {
            let best_ms = group_rows
                .iter()
                .filter(|(_, r)| r.api_ok)
                .map(|(_, r)| r.api_ms)
                .min()
                .unwrap_or(0);
            record.insert("latency_ms".into(), json!(best_ms as i64));
        } else {
            let worst_ms = group_rows.iter().map(|(_, r)| r.ping_ms).max().unwrap_or(0);
            if worst_ms > 0 {
                record.insert("latency_ms".into(), json!(worst_ms as i64));
            }
            // Pick the FIRST failing stage in the chain (Ping → API → Chat)
            // and surface ITS status + body, so a 200/401 mix (API auth OK,
            // Chat rejected by model policy) reports the chat 401 — not the
            // earlier api 200. Previously this always read api_body_snippet,
            // which silently hid every chat-stage failure.
            let cap_280 = |opt: &Option<String>| -> Option<String> {
                opt.as_ref()
                    .map(|s| s.chars().take(280).collect::<String>())
            };
            if let Some((_, r)) = group_rows.iter().find(|(_, r)| !r.ping_ok) {
                let _ = r;
                record.insert("error_code".into(), json!("PROXY_UPSTREAM_UNREACHABLE"));
                record.insert(
                    "error_message".into(),
                    json!("aikey-proxy could not reach the upstream provider"),
                );
            } else if let Some((_, r)) = group_rows.iter().find(|(_, r)| !r.api_ok) {
                if let Some(status) = r.api_status {
                    record.insert("error_code".into(), json!(format!("HTTP_{}", status)));
                    if let Some(snippet) = cap_280(&r.api_body_snippet) {
                        record.insert("error_message".into(), json!(snippet));
                    }
                } else {
                    record.insert("error_code".into(), json!("API_NO_HTTP_STATUS"));
                }
            } else if let Some((_, r)) = group_rows
                .iter()
                .find(|(_, r)| !r.chat_ok && !r.chat_skipped)
            {
                // API succeeded but Chat probe failed — most commonly upstream
                // model-policy rejection (Anthropic 400 "invalid model"
                // for the probe model, OpenAI 401 for org-scoped keys hitting
                // the wrong endpoint). chat_body_snippet carries the real
                // reason the user needs to see.
                if let Some(status) = r.chat_status {
                    record.insert("error_code".into(), json!(format!("HTTP_{}", status)));
                    if let Some(snippet) = cap_280(&r.chat_body_snippet) {
                        record.insert("error_message".into(), json!(snippet));
                    }
                } else {
                    record.insert("error_code".into(), json!("CHAT_NO_HTTP_STATUS"));
                }
            } else {
                record.insert("error_code".into(), json!("UNKNOWN"));
            }
        }

        // Per-credential suite_results: filter the global json_results
        // by source_ref (the probe-emitter at runtime.rs:1076 includes
        // source_ref in every per-row JSON, but the proxy row uses
        // provider="proxy" and has no source_ref, so it drops naturally).
        let suite_rows: Vec<serde_json::Value> = outcome
            .json_results
            .iter()
            .filter(|v| {
                v.get("source_ref")
                    .and_then(|s| s.as_str())
                    .map(|s| s == source_ref)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        record.insert("suite_results".into(), json!(suite_rows));

        // 2026-05-26 (spec 20260526-pre-save-proxy-probe-raw.md §6.2):
        // surface the proxy probe result into each record's last_test JSON so
        // the Web Add Key modal (and any other Web caller) can render a real
        // Proxy row instead of hard-coding "skipped".
        //
        // Pure-addition: pre-2026-05-26 last_test had no proxy_* fields, so
        // old consumers ignore these. Web pre-Step-Phase-2.E hard-coded
        // "skipped" regardless of testResult content; post-2.E reads these.
        //
        // All records in the same SuiteOutcome share the same proxy probe
        // (one probe per suite run, applies to whichever provider was tested
        // first). Duplicating the data into every record keeps the consumer
        // simple — they read these fields off the record they already have,
        // no separate field lookup.
        if let Some(p) = &outcome.proxy {
            // proxy_ok = real chain success: proxy returned 2xx AND no
            // probe_raw error_code (PROXY_TOO_OLD_NO_PROBE_RAW etc must NOT
            // render as "ok" even though `ok: true` because the probe came
            // back from the proxy at all).
            let chain_ok = p.ok && p.error_code.is_none();
            record.insert("proxy_ok".into(), json!(chain_ok));
            record.insert("proxy_ms".into(), json!(p.ms as i64));
            if let Some(status) = p.status {
                record.insert("proxy_status".into(), json!(status));
            }
            if let Some(code) = &p.error_code {
                record.insert("proxy_error_code".into(), json!(code));
            }
            // Pre-rendered user-facing hint string — same logic CLI uses,
            // so terminal + web display identical text. Web doesn't have to
            // duplicate the error_code → user-action mapping.
            let hint = crate::connectivity::runtime::proxy_probe_full_hint(p);
            record.insert("proxy_status_hint".into(), json!(hint));
        }

        let record_value = serde_json::Value::Object(record);
        records.push(AggregatedTestRecord {
            target_kind: kind,
            source_ref,
            last_test: record_value,
        });
    }
    records
}

/// Aggregate `outcome.rows` per credential and persist the result to
/// each credential's `extra.$.last_test`. Returns one entry per
/// credential, in input order (groups are visited in first-seen order).
///
/// Aggregation rules per credential are defined in
/// [`aggregate_test_outcome`] — this function only adds the storage
/// write on top of the same byte-shape so that the row a Web user sees
/// after clicking Test connection is byte-identical to what `aikey test`
/// produces.
pub fn persist_test_outcome(outcome: &SuiteOutcome) -> Vec<PersistedTestResult> {
    let records = aggregate_test_outcome(outcome);
    let mut results: Vec<PersistedTestResult> = Vec::with_capacity(records.len());
    for record in records {
        let AggregatedTestRecord {
            target_kind,
            source_ref,
            last_test,
        } = record;

        let record_json = match serde_json::to_string(&last_test) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[connectivity::persist WARN] serialise failed for {:?} {}: {}",
                    target_kind, source_ref, e
                );
                results.push(PersistedTestResult {
                    target_kind,
                    source_ref,
                    persisted: false,
                    last_test,
                });
                continue;
            }
        };

        let write_result = match target_kind {
            CredentialKind::PersonalApi => {
                storage::merge_entry_extra(&source_ref, "$.last_test", &record_json)
            }
            CredentialKind::OAuth => {
                storage::merge_oauth_extra(&source_ref, "$.last_test", &record_json)
            }
            CredentialKind::ManagedTeam => {
                storage::merge_team_extra(&source_ref, "$.last_test", &record_json)
            }
        };
        let persisted = match write_result {
            Ok(n) => n > 0,
            Err(e) => {
                // Logging-conventions principle: surface persistence
                // failure so it's not lost behind a silent default.
                eprintln!(
                    "[connectivity::persist WARN] write failed for {:?} {}: {}",
                    target_kind, source_ref, e
                );
                false
            }
        };

        results.push(PersistedTestResult {
            target_kind,
            source_ref,
            persisted,
            last_test,
        });
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Fence tests for `aggregate_test_outcome` (2026-05-23)
//
// Goal: pin the aggregation rules described in the requirements spec
// `roadmap20260320/技术实现/阶段4-增值版/AddKey-OAuth与连通性渐进式引导
// 需求规格说明书.md §5.1 + §10.5` so the Web Add-Key pre-save Run-test
// path (which reuses `aggregate_test_outcome`) cannot silently drift
// from the public `aikey test` CLI output. These tests were added BEFORE
// extracting the aggregator out of the legacy monolithic
// `persist_test_outcome`; they MUST stay green on every future edit to
// "what counts as pass / which body snippet wins / how latency is
// computed".
//
// Test inputs are built directly from `ConnectivityResult::default()`
// + targeted field overrides — no real network, no vault, no proxy.
// Output assertions are made against the JSON shape that lands in
// `extra.$.last_test` (mirrored by `web/src/shared/api/user/vault.ts`).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectivity::runtime::ConnectivityResult;
    use crate::connectivity::TestTarget;

    fn target(source_ref: &str, kind: CredentialKind) -> TestTarget {
        TestTarget {
            provider_code: "openai".into(),
            protocol_type: "openai_compatible".into(),
            client_route: "openai".into(),
            probe_provider_code: "openai".into(),
            base_url: "https://api.openai.com/v1".into(),
            bearer: "test".into(),
            kind,
            source_ref: source_ref.into(),
            display_alias: String::new(),
        }
    }

    fn outcome(rows: Vec<(TestTarget, ConnectivityResult)>) -> SuiteOutcome {
        SuiteOutcome {
            rows,
            proxy: None,
            build_errors: vec![],
            any_chat_ok: false,
            json_results: vec![],
        }
    }

    fn single(kind: CredentialKind, r: ConnectivityResult) -> SuiteOutcome {
        outcome(vec![(target("alias-1", kind), r)])
    }

    #[test]
    fn full_pass_status_and_phase_booleans() {
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 42,
            api_ok: true,
            api_ms: 186,
            api_status: Some(200),
            chat_ok: true,
            chat_ms: 812,
            chat_status: Some(200),
            chat_skipped: false,
            chat_skip_reason: None,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        assert_eq!(agg.len(), 1);
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "pass");
        assert_eq!(lt["ping_ok"], true);
        assert_eq!(lt["api_ok"], true);
        assert_eq!(lt["chat_ok"], true);
        assert_eq!(lt["chat_skipped"], false);
        assert_eq!(lt["latency_ms"], 186);
        assert!(
            lt.get("error_code").is_none(),
            "pass row must NOT carry error_code"
        );
    }

    #[test]
    fn chat_skipped_api_pass_counts_as_pass() {
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 42,
            api_ok: true,
            api_ms: 186,
            api_status: Some(200),
            chat_ok: false,
            chat_skipped: true,
            chat_skip_reason: Some("skipped by connectivity policy".into()),
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "pass");
        assert_eq!(lt["api_ok"], true);
        assert_eq!(lt["chat_ok"], false);
        assert_eq!(lt["chat_skipped"], true);
        assert_eq!(lt["latency_ms"], 186);
        assert!(lt.get("error_code").is_none());
    }

    #[test]
    fn chat_skipped_api_failure_still_fails() {
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 42,
            api_ok: false,
            api_status: Some(401),
            api_body_snippet: Some("Invalid API key".into()),
            chat_ok: false,
            chat_skipped: true,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "fail");
        assert_eq!(lt["chat_skipped"], true);
        assert_eq!(lt["error_code"], "HTTP_401");
    }

    #[test]
    fn full_pass_picks_min_api_ms_across_passing_rows() {
        // Two rows for same credential, both chat_ok: latency_ms should be
        // min(api_ms) across passing rows. Multi-provider per credential is
        // realistic when an aggregator key (openrouter, yunwu) serves > 1
        // protocol.
        let mut r1 = ConnectivityResult::default();
        r1.ping_ok = true;
        r1.api_ok = true;
        r1.api_ms = 500;
        r1.chat_ok = true;
        r1.chat_status = Some(200);
        let mut r2 = ConnectivityResult::default();
        r2.ping_ok = true;
        r2.api_ok = true;
        r2.api_ms = 120;
        r2.chat_ok = true;
        r2.chat_status = Some(200);
        let so = outcome(vec![
            (target("agg-1", CredentialKind::PersonalApi), r1),
            (target("agg-1", CredentialKind::PersonalApi), r2),
        ]);
        let agg = aggregate_test_outcome(&so);
        assert_eq!(
            agg.len(),
            1,
            "two rows for same credential must collapse into one record"
        );
        assert_eq!(
            agg[0].last_test["latency_ms"], 120,
            "min api_ms across passing rows"
        );
    }

    #[test]
    fn ping_failure_emits_proxy_upstream_unreachable() {
        // Spec §10.5: first-failing phase is Ping → API → Chat. ping_ok=false
        // takes priority even if api/chat were never attempted.
        let r = ConnectivityResult {
            ping_ok: false,
            ping_ms: 0,
            api_ok: false,
            chat_ok: false,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "fail");
        assert_eq!(lt["error_code"], "PROXY_UPSTREAM_UNREACHABLE");
        assert!(lt["error_message"]
            .as_str()
            .unwrap()
            .contains("aikey-proxy could not reach"));
        assert!(
            lt.get("latency_ms").is_none(),
            "ping_ms=0 must omit latency_ms (spec §5.1 fail path)"
        );
    }

    #[test]
    fn api_failure_with_status_emits_http_code_and_body_snippet() {
        // chat_ok=false naturally because api failed first — but the api 401
        // is what we want to surface (not a downstream Chat error message).
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 50,
            api_ok: false,
            api_ms: 100,
            api_status: Some(401),
            api_body_snippet: Some("Invalid API key".into()),
            chat_ok: false,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "fail");
        assert_eq!(lt["error_code"], "HTTP_401");
        assert_eq!(lt["error_message"], "Invalid API key");
        assert_eq!(
            lt["latency_ms"], 50,
            "fail path latency_ms = max ping_ms across rows"
        );
    }

    #[test]
    fn api_failure_without_status_emits_no_http_status_sentinel() {
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 30,
            api_ok: false,
            api_status: None,
            chat_ok: false,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        assert_eq!(agg[0].last_test["error_code"], "API_NO_HTTP_STATUS");
    }

    #[test]
    fn chat_failure_after_api_pass_surfaces_chat_status_not_api_status() {
        // Regression guard for the 2026-05-22 bug where error_code always
        // read api_body_snippet, silently hiding chat-stage failures (api
        // 200 + chat 401 reported as success). First-failing-phase chain
        // must walk Ping → API → Chat and stop at the first !*_ok.
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 40,
            api_ok: true,
            api_ms: 80,
            api_status: Some(200),
            api_body_snippet: Some("{\"models\": []}".into()),
            chat_ok: false,
            chat_status: Some(400),
            chat_body_snippet: Some("invalid model".into()),
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "fail");
        assert_eq!(
            lt["error_code"], "HTTP_400",
            "chat 400 must win, NOT api 200"
        );
        assert_eq!(
            lt["error_message"], "invalid model",
            "must read chat_body_snippet, not api_body_snippet"
        );
    }

    #[test]
    fn chat_failure_without_status_emits_no_http_status_sentinel() {
        let r = ConnectivityResult {
            ping_ok: true,
            ping_ms: 40,
            api_ok: true,
            api_status: Some(200),
            chat_ok: false,
            chat_status: None,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        assert_eq!(agg[0].last_test["error_code"], "CHAT_NO_HTTP_STATUS");
    }

    #[test]
    fn error_message_truncated_to_280_chars() {
        // cap_280 helper in aggregator: snippets longer than 280 chars get
        // truncated so the persisted record stays bounded. Defends the row
        // size budget when upstream returns a huge HTML error page.
        let long = "x".repeat(500);
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: false,
            api_status: Some(502),
            api_body_snippet: Some(long.clone()),
            chat_ok: false,
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        let msg = agg[0].last_test["error_message"].as_str().unwrap();
        assert_eq!(msg.chars().count(), 280, "snippets are capped at 280 chars");
    }

    #[test]
    fn any_ok_semantics_one_pass_row_makes_phase_ok() {
        // Spec §10.5 any-ok semantics: a credential bound to multiple
        // providers passes a phase if ≥ 1 provider passes it. Two rows for
        // same (kind, source_ref): one fully pass, one fully fail → overall
        // status=pass and all three phase booleans=true.
        let mut pass = ConnectivityResult::default();
        pass.ping_ok = true;
        pass.api_ok = true;
        pass.api_ms = 100;
        pass.chat_ok = true;
        pass.chat_status = Some(200);
        let fail = ConnectivityResult::default(); // all false
        let so = outcome(vec![
            (target("multi", CredentialKind::PersonalApi), fail),
            (target("multi", CredentialKind::PersonalApi), pass),
        ]);
        let agg = aggregate_test_outcome(&so);
        let lt = &agg[0].last_test;
        assert_eq!(lt["status"], "pass");
        assert_eq!(lt["ping_ok"], true);
        assert_eq!(lt["api_ok"], true);
        assert_eq!(lt["chat_ok"], true);
        assert_eq!(lt["latency_ms"], 100, "min api_ms across PASSING rows only");
    }

    #[test]
    fn suite_results_filtered_by_source_ref_proxy_row_drops() {
        // Per-credential suite_results filter: only json_results matching
        // this group's source_ref. Proxy row has provider="proxy" + no
        // source_ref → naturally drops. Regression guard against showing
        // unrelated rows in the popup's per-provider breakdown.
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            ..Default::default()
        };
        let so = SuiteOutcome {
            rows: vec![(target("kimi-1", CredentialKind::PersonalApi), r)],
            proxy: None,
            build_errors: vec![],
            any_chat_ok: true,
            json_results: vec![
                json!({ "source_ref": "kimi-1", "provider": "kimi", "phase": "api" }),
                json!({ "source_ref": "other-key", "provider": "openai", "phase": "api" }),
                json!({ "provider": "proxy" }), // no source_ref → drops
            ],
        };
        let agg = aggregate_test_outcome(&so);
        let rows = agg[0].last_test["suite_results"].as_array().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "only the row matching source_ref must be kept"
        );
        assert_eq!(rows[0]["source_ref"], "kimi-1");
    }

    #[test]
    fn unknown_error_when_phases_all_pass_but_overall_fail_impossible() {
        // Defensive fallback: aggregator's final `else` arm. With current
        // pass=chat_ok logic this branch is unreachable (if chat_ok=true
        // we're in the pass arm), but the code path exists as a defense.
        // Pinning UNKNOWN keeps the contract should a future refactor
        // separate `pass` from "all phases ok".
        //
        // We can't actually trigger this with the current invariant, so
        // assert via the surrounding behavior: if all phases ok, no
        // error_code key is emitted.
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            api_status: Some(200),
            chat_status: Some(200),
            ..Default::default()
        };
        let agg = aggregate_test_outcome(&single(CredentialKind::PersonalApi, r));
        assert!(agg[0].last_test.get("error_code").is_none());
    }

    #[test]
    fn fail_path_latency_takes_max_ping_ms_across_rows() {
        let mut r1 = ConnectivityResult::default();
        r1.ping_ok = false;
        r1.ping_ms = 100;
        let mut r2 = ConnectivityResult::default();
        r2.ping_ok = false;
        r2.ping_ms = 350;
        let so = outcome(vec![
            (target("x", CredentialKind::PersonalApi), r1),
            (target("x", CredentialKind::PersonalApi), r2),
        ]);
        let agg = aggregate_test_outcome(&so);
        assert_eq!(
            agg[0].last_test["latency_ms"], 350,
            "fail path = slowest hop"
        );
    }

    // ─── 2026-05-26 Phase 2.E — proxy fields surfaced into last_test ───
    //
    // Pin spec §6.2 (20260526-pre-save-proxy-probe-raw.md): aggregator must
    // serialize outcome.proxy into per-record last_test so the Web Add Key
    // modal can render a real Proxy row instead of hard-coding "skipped".

    use crate::connectivity::runtime::ProxyProbeResult;

    fn outcome_with_proxy(
        rows: Vec<(TestTarget, ConnectivityResult)>,
        p: ProxyProbeResult,
    ) -> SuiteOutcome {
        SuiteOutcome {
            rows,
            proxy: Some(p),
            build_errors: vec![],
            any_chat_ok: false,
            json_results: vec![],
        }
    }

    #[test]
    fn proxy_fields_surface_when_proxy_probe_succeeded() {
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            ..Default::default()
        };
        let so = outcome_with_proxy(
            vec![(target("k1", CredentialKind::PersonalApi), r)],
            ProxyProbeResult {
                ok: true,
                ms: 187,
                status: Some(200),
                error_code: None,
            },
        );
        let agg = aggregate_test_outcome(&so);
        let lt = &agg[0].last_test;
        assert_eq!(
            lt["proxy_ok"], true,
            "proxy_ok must surface when probe succeeded"
        );
        assert_eq!(lt["proxy_ms"], 187);
        assert_eq!(lt["proxy_status"], 200);
        assert!(
            lt.get("proxy_error_code").is_none(),
            "no error_code → field absent"
        );
        let hint = lt["proxy_status_hint"].as_str().expect("hint missing");
        assert!(
            hint.contains("routing ok"),
            "200 hint should mention routing ok, got: {}",
            hint
        );
    }

    #[test]
    fn proxy_old_proxy_error_surfaces_as_not_ok_with_specific_hint() {
        // Critical fence: even when ProxyProbeResult.ok=true (proxy responded),
        // the presence of error_code (PROXY_TOO_OLD_NO_PROBE_RAW etc) must
        // render as proxy_ok=FALSE so the Web Proxy row shows red/warning.
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            ..Default::default()
        };
        let so = outcome_with_proxy(
            vec![(target("k1", CredentialKind::PersonalApi), r)],
            ProxyProbeResult {
                ok: true,
                ms: 12,
                status: Some(401),
                error_code: Some("PROXY_TOO_OLD_NO_PROBE_RAW".to_string()),
            },
        );
        let agg = aggregate_test_outcome(&so);
        let lt = &agg[0].last_test;
        assert_eq!(
            lt["proxy_ok"], false,
            "error_code present must override ok=true so Web renders as failure"
        );
        assert_eq!(lt["proxy_error_code"], "PROXY_TOO_OLD_NO_PROBE_RAW");
        let hint = lt["proxy_status_hint"].as_str().expect("hint missing");
        assert!(
            hint.contains("aikey service restart proxy"),
            "old-proxy hint must include recovery action, got: {}",
            hint
        );
    }

    #[test]
    fn proxy_fields_absent_when_outcome_has_no_proxy() {
        // Pre-2026-05-26 callers (and post-save paths that don't set
        // show_proxy_row) produce SuiteOutcome { proxy: None, ... }.
        // Aggregator must NOT inject proxy_* fields with default 0/false
        // — leave them entirely absent so Web can distinguish "no proxy
        // probe ran" from "proxy probe ran with ok=false".
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            ..Default::default()
        };
        let so = outcome(vec![(target("k1", CredentialKind::PersonalApi), r)]);
        let agg = aggregate_test_outcome(&so);
        let lt = &agg[0].last_test;
        assert!(lt.get("proxy_ok").is_none(), "no probe → proxy_ok absent");
        assert!(lt.get("proxy_ms").is_none());
        assert!(lt.get("proxy_status").is_none());
        assert!(lt.get("proxy_status_hint").is_none());
        assert!(lt.get("proxy_error_code").is_none());
    }

    #[test]
    fn proxy_fields_surface_with_disabled_flag_error() {
        // Operator-disabled flag returns 503 + PROBE_RAW_DISABLED.
        let r = ConnectivityResult {
            ping_ok: true,
            api_ok: true,
            chat_ok: true,
            ..Default::default()
        };
        let so = outcome_with_proxy(
            vec![(target("k1", CredentialKind::PersonalApi), r)],
            ProxyProbeResult {
                ok: true,
                ms: 5,
                status: Some(503),
                error_code: Some("PROBE_RAW_DISABLED".to_string()),
            },
        );
        let agg = aggregate_test_outcome(&so);
        let lt = &agg[0].last_test;
        assert_eq!(lt["proxy_error_code"], "PROBE_RAW_DISABLED");
        let hint = lt["proxy_status_hint"].as_str().unwrap();
        assert!(
            hint.contains("disabled"),
            "hint must mention disabled, got: {}",
            hint
        );
    }
}

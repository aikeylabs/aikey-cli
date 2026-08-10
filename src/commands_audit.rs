//! `aikey audit` — financial-grade delivery-integrity audit (stage D2).
//!
//! Read-only view of the collector's per-source completeness (NO vault password
//! needed — it only reads an unauthenticated diagnostics endpoint): allocated /
//! confirmed seq high-water, open gaps, documented known losses, and quarantined
//! (content-hash-failed) events.
//!
//!   - `aikey audit status`    — show the current per-source completeness table.
//!   - `aikey audit reconcile` — force an immediate server-side scan + known-loss
//!     promotion (so a gap stale past KnownLossTimeout settles into the audit
//!     ledger now instead of on the next periodic tick), then show the verdict.
//!
//! The completeness/reconcile endpoints live on the local collector (the
//! local-server on Personal/Trial; the standalone collector on Production). We
//! reach it on 127.0.0.1 at the local-server port, mirroring `aikey doctor`.
//!
//! ## Why the compliance lane is rendered here too (2026-08-10)
//!
//! `/admin/audit/status` is the ONE place an operator looks to ask "is anything
//! undelivered on this box?". Until the compliance dead-letter work it only ever
//! answered for USAGE, so a stalled proxy→Control Panel compliance pipeline was
//! invisible — the audit page was empty and nothing said why (see
//! `workflow/CI/bugfix/20260810-compliance-upload-failure-is-permanent-audit-loss.md`).
//! The endpoint now carries a `compliance` object; this renderer is the last mile
//! that turns it into something a human actually reads. A machine-readable
//! endpoint nobody surfaces is not a health signal.

use std::time::Duration;

use colored::Colorize;

use crate::local_server_probe;

const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Resolve the local collector base URL (http://127.0.0.1:<port>).
fn audit_base() -> Result<String, String> {
    let port = local_server_probe::read_local_server_port_or_default()?;
    Ok(format!("http://127.0.0.1:{}", port))
}

fn fetch(req: ureq::Request, base: &str) -> Result<serde_json::Value, String> {
    match req.timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS)).call() {
        Ok(resp) => resp
            .into_json::<serde_json::Value>()
            .map_err(|e| format!("parse response: {}", e)),
        Err(e) => Err(format!(
            "delivery-integrity endpoint not reachable at {} ({}).\nStart the local service with:\n    {}",
            base,
            e,
            local_server_probe::start_command_hint()
        )),
    }
}

/// Best-effort GET of the proxy's local audit status (D2.5). None if the proxy
/// isn't running — the server view still works without it.
fn fetch_proxy_status() -> Option<serde_json::Value> {
    let addr = crate::commands_proxy::proxy_listen_addr(None);
    let url = format!("http://{}/admin/audit/status", addr);
    ureq::get(&url)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .call()
        .ok()?
        .into_json()
        .ok()
}

/// `aikey audit status` — server completeness table + best-effort local client
/// (proxy) state.
pub fn handle_status(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let base = audit_base()?;
    let data = fetch(
        ureq::get(&format!("{}/v1/diagnostics/completeness", base)),
        &base,
    )?;
    let local = fetch_proxy_status();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"server": data, "local": local}))?
        );
        return Ok(());
    }
    print_table(&base, &data, "Delivery audit");
    print_local_status(local.as_ref());
    Ok(())
}

/// `aikey audit reconcile` — trigger reconciliation, then show the settled table
/// + verdict. Prefers the PROXY's client-confirmed pass (re-send WAL-present
/// gaps, confirm WAL-absent gaps lost now); falls back to the collector's
/// server-timeout reconcile when the proxy isn't reachable.
pub fn handle_reconcile(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let base = audit_base()?;
    let (mode, client_result) = trigger_reconcile(&base);
    // Settled view — best-effort so a momentarily-down collector degrades to the
    // mode message instead of erroring out before it can print.
    let data = fetch(
        ureq::get(&format!("{}/v1/diagnostics/completeness", base)),
        &base,
    )
    .ok();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode": mode, "client_result": client_result, "server": data
            }))?
        );
        return Ok(());
    }
    match (mode.as_str(), client_result.as_ref()) {
        ("client", Some(c)) => {
            let resent = c["resent"].as_i64().unwrap_or(0);
            println!(
                "Reconcile (client-confirmed) — re-sent {} recoverable, confirmed {} lost{}.",
                resent,
                c["confirmed_lost"].as_i64().unwrap_or(0),
                if c["still_missing"].as_i64().unwrap_or(0) > 0 {
                    " (more remain — re-run reconcile)"
                } else {
                    ""
                },
            );
            // Honesty: "re-sent" counts gaps re-uploaded from the WAL this pass,
            // NOT server-acked deliveries — a re-send that fails dead-letters and
            // is still counted here. So don't let the user read it as "confirmed
            // landed"; point them at the authoritative completeness view, which
            // only advances `confirmed` once the server actually ingested.
            if resent > 0 {
                println!(
                    "  (re-sent = re-uploaded best-effort; confirm landing with `aikey audit status`.)"
                );
            }
            println!();
        }
        ("client", None) => {
            println!(
                "Reconcile (client-confirmed) — triggered on the proxy (no detail returned).\n"
            );
        }
        ("server", _) => {
            println!("Reconcile (server-only — proxy not reachable) — promoted stale gaps to known-loss.\n");
        }
        _ => {
            println!(
                "Reconcile — could not reach the proxy or collector to trigger reconciliation.\n"
            );
        }
    }
    match data {
        Some(d) => {
            print_table(&base, &d, "Reconcile");
            print_verdict(&d);
        }
        None => {
            println!("  (server completeness unavailable — could not display the settled state)")
        }
    }
    Ok(())
}

/// trigger_reconcile prefers the proxy's client-confirmed pass; on failure falls
/// back to the collector's server-timeout reconcile. Returns (mode, client_json).
fn trigger_reconcile(collector_base: &str) -> (String, Option<serde_json::Value>) {
    let addr = crate::commands_proxy::proxy_listen_addr(None);
    let proxy_url = format!("http://{}/admin/audit/reconcile", addr);
    if let Ok(resp) = ureq::post(&proxy_url)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .call()
    {
        return ("client".to_string(), resp.into_json().ok());
    }
    // Fallback: collector server-timeout reconcile (promotes ≥KnownLossTimeout gaps).
    if ureq::post(&format!("{}/v1/diagnostics/reconcile", collector_base))
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .call()
        .is_ok()
    {
        return ("server".to_string(), None);
    }
    ("none".to_string(), None)
}

fn print_local_status(local: Option<&serde_json::Value>) {
    print!("{}", render_local_status(local));
}

/// Renders the "Local client (proxy)" block: the usage lane's delivery state
/// plus the compliance lane's queue. Returns the text (newline-terminated) so
/// the shape is unit-testable without capturing stdout.
fn render_local_status(local: Option<&serde_json::Value>) -> String {
    let Some(l) = local else {
        return "\n  Local client (proxy): not reachable (run `aikey proxy status`).\n".to_string();
    };
    let rep = &l["reporter"];
    let mut out = format!(
        "\n  Local client (proxy): allocated={} WAL-files={} dead-letter={} last-upload={}\n",
        l["allocated_seq"].as_i64().unwrap_or(0),
        l["wal_files"].as_i64().unwrap_or(0),
        l["dead_letter_count"].as_i64().unwrap_or(0),
        rep["last_upload_status"].as_str().unwrap_or("n/a"),
    );
    out.push_str(&render_compliance_status(l.get("compliance")));
    out
}

/// Renders the compliance (proxy → Control Panel) delivery lane.
///
/// Three shapes, deliberately distinguishable:
///   * `None` / non-object — the proxy predates the compliance queue reporting.
///     Rendered as UNAVAILABLE, never as `0`: a zero here would read as "healthy"
///     while the box is in fact un-monitored (CLAUDE.md: no-lazy-defaults —
///     a missing field must not be silently defaulted into a reassuring value).
///   * queue empty — one quiet healthy line.
///   * queue non-empty — loud, with the failure attribution and the exact next
///     command, because a non-empty queue means audit records exist that the
///     Control Panel has NOT got yet.
fn render_compliance_status(compliance: Option<&serde_json::Value>) -> String {
    const LABEL: &str = "Compliance upload (proxy → Control Panel)";

    let Some(c) = compliance.filter(|c| c.is_object()) else {
        return format!(
            "  {} {}: not reported by this proxy (older build)\n      \
             {} A stalled compliance queue would be INVISIBLE here. Upgrade aikey on this \
             machine, then `aikey proxy restart`.\n",
            crate::symbols::WARN.s().yellow(),
            LABEL,
            crate::symbols::HINT_ARROW.s(),
        );
    };

    let entries = c["dead_letter_entries"].as_i64().unwrap_or(0);
    let events = c["dead_letter_events"].as_i64().unwrap_or(0);
    let failure = render_compliance_failure(c);

    if entries <= 0 {
        // Empty queue is the healthy state even if this process saw a failure
        // earlier — the queue drained, so say so rather than keep alarming.
        let recovered = match failure {
            Some(f) => format!(" (last failure {}; queue since drained)", f),
            None => String::new(),
        };
        return format!(
            "  {} {}: nothing queued{}\n",
            crate::symbols::CHECK.s().green(),
            LABEL,
            recovered
        );
    }

    let mut out = format!(
        "  {} {}: {}\n",
        crate::symbols::WARN.s().yellow(),
        LABEL,
        format!(
            "{} batch(es) / {} event(s) queued — these audit records are NOT delivered yet",
            entries, events
        )
        .yellow()
    );
    if let Some(f) = &failure {
        out.push_str(&format!("      Last failure: {}\n", f));
    }
    // Next step. A 400 is the version-skew signature: the Control Panel decodes
    // strictly, so a proxy newer than the server gets its batches rejected until
    // the server catches up. Same bytes succeed after the upgrade — which is why
    // they are queued rather than dropped.
    if c["last_failure_code"].as_i64() == Some(400) {
        out.push_str(&format!(
            "      {} Looks like version skew: the Control Panel is older than this proxy and \
             rejects the payload.\n         Upgrade the Control Panel, then run \
             `aikey proxy replay-dead-letter` to deliver the queue.\n",
            crate::symbols::HINT_ARROW.s(),
        ));
    } else {
        out.push_str(&format!(
            "      {} Fix the cause above (Control Panel reachable? credentials valid?), then run \
             `aikey proxy replay-dead-letter` to deliver the queue.\n",
            crate::symbols::HINT_ARROW.s(),
        ));
    }
    out
}

/// "12m ago, HTTP 400: <reason>" from whichever of the three failure fields the
/// proxy actually sent (each is `omitempty`). None when this process has not
/// seen a compliance upload fail.
fn render_compliance_failure(c: &serde_json::Value) -> Option<String> {
    let at = c["last_failure_at"].as_i64().unwrap_or(0);
    let code = c["last_failure_code"].as_i64().unwrap_or(0);
    let raw_reason = c["last_failure_reason"].as_str().unwrap_or("").trim();
    if at == 0 && code == 0 && raw_reason.is_empty() {
        return None;
    }
    // The proxy builds the reason as "<status>: <body excerpt>", so printing it
    // after our own "HTTP <code>" would read "HTTP 400: 400: {...}". Drop the
    // duplicated prefix, never the body.
    let reason = match code > 0 {
        true => raw_reason
            .strip_prefix(&format!("{}:", code))
            .unwrap_or(raw_reason)
            .trim(),
        false => raw_reason,
    };
    let mut parts: Vec<String> = Vec::new();
    if at > 0 {
        parts.push(format_millis_ago(at));
    }
    if code > 0 {
        parts.push(format!("HTTP {}", code));
    }
    let head = if parts.is_empty() {
        String::new()
    } else {
        parts.join(", ")
    };
    Some(match (head.is_empty(), reason.is_empty()) {
        (true, _) => truncate(reason, 160),
        (false, true) => head,
        (false, false) => format!("{}: {}", head, truncate(reason, 160)),
    })
}

/// Relative age of a Unix-epoch-millis instant, matching the CLI's existing
/// "Xs/Xm/Xh/Xd ago" convention (`commands_watch`, `commands_statusline`).
/// Relative on purpose: no locale and no display-time-zone lookup, so this
/// stays readable on a box whose vault is locked.
fn format_millis_ago(unix_millis: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(unix_millis);
    let secs = ((now_ms - unix_millis) / 1000).max(0);
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn print_table(base: &str, data: &serde_json::Value, title: &str) {
    let empty = vec![];
    let sources = data["sources"].as_array().unwrap_or(&empty);
    println!("{} — {}\n", title, base);
    if sources.is_empty() {
        println!("  (no sources reporting yet)");
        return;
    }
    println!(
        "  {:<38} {:>9} {:>9} {:>7} {:>5} {:>10} {:>10}  {}",
        "SOURCE", "ALLOCATED", "CONFIRMED", "PENDING", "GAPS", "KNOWN-LOSS", "QUARANTINE", "STATUS"
    );
    for s in sources {
        let alloc = s["client_allocated_seq"].as_i64().unwrap_or(0);
        let conf = s["contiguous_seq"].as_i64().unwrap_or(0);
        // PENDING = allocated-but-not-yet-confirmed (in flight); never negative.
        let pending = (alloc - conf).max(0);
        println!(
            "  {:<38} {:>9} {:>9} {:>7} {:>5} {:>10} {:>10}  {}",
            truncate(s["source_id"].as_str().unwrap_or("?"), 38),
            alloc,
            conf,
            pending,
            s["gap_count"].as_i64().unwrap_or(0),
            s["known_loss_count"].as_i64().unwrap_or(0),
            s["quarantine_count"].as_i64().unwrap_or(0),
            s["status"].as_str().unwrap_or("?"),
        );
    }
    let healthy = data["healthy"].as_bool().unwrap_or(false);
    println!(
        "\n  Overall: {}  ({} source(s), {} with gaps, {} quarantined)",
        if healthy { "healthy" } else { "ATTENTION" },
        sources.len(),
        data["gap_sources"].as_i64().unwrap_or(0),
        data["quarantine_total"].as_i64().unwrap_or(0),
    );
}

fn print_verdict(data: &serde_json::Value) {
    let empty = vec![];
    let sources = data["sources"].as_array().unwrap_or(&empty);
    if sources.is_empty() {
        return;
    }
    println!("\n  Verdict:");
    for s in sources {
        let src = truncate(s["source_id"].as_str().unwrap_or("?"), 38);
        let kl = s["known_loss_count"].as_i64().unwrap_or(0);
        // Still-open = unaccounted seqs (middle holes + unaccounted tail).
        let open = s["gap_count"].as_i64().unwrap_or(0) + s["tail_pending"].as_i64().unwrap_or(0);
        if open == 0 {
            println!("    {}: reconciled — {} documented loss(es)", src, kl);
        } else {
            println!(
                "    {}: {} still missing, {} documented loss(es)",
                src, open, kl
            );
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{}…", head)
    }
}

/// Fences the compliance lane's rendering against the three wire shapes
/// `/admin/audit/status` can actually produce. The regression these pin down is
/// the one from 2026-08-10: a compliance pipeline can be stalled while every
/// number an operator looks at reads "fine".
#[cfg(test)]
mod compliance_render_tests {
    use super::*;
    use serde_json::json;

    /// Colour is a tty-dependent global in `colored`; assert on the text.
    fn plain(v: Option<&serde_json::Value>) -> String {
        crate::style::strip_sgr(&render_local_status(v)).into_owned()
    }

    /// Shape 1 — current proxy, compliance lane idle. Exactly one quiet line;
    /// must NOT claim a failure and must not print a next-step nag.
    #[test]
    fn healthy_compliance_renders_one_quiet_line() {
        let out = plain(Some(&json!({
            "source_id": "src-1",
            "allocated_seq": 256,
            "wal_files": 32,
            "dead_letter_count": 0,
            "reporter": {"last_upload_status": "ok"},
            "compliance": {"dead_letter_entries": 0, "dead_letter_events": 0},
        })));
        assert!(
            out.contains("Compliance upload (proxy → Control Panel): nothing queued"),
            "healthy line missing: {}",
            out
        );
        assert!(!out.contains("Last failure"), "spurious failure: {}", out);
        assert!(
            !out.contains("replay-dead-letter"),
            "nagging with an empty queue: {}",
            out
        );
    }

    /// Shape 2 — backlog from a version-skew 400. The operator must see the
    /// depth, the attribution, and the exact recovery command.
    #[test]
    fn backlogged_compliance_is_loud_and_actionable() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let out = plain(Some(&json!({
            "source_id": "src-1",
            "allocated_seq": 256,
            "wal_files": 32,
            "dead_letter_count": 3,
            "reporter": {"last_upload_status": "ok"},
            "compliance": {
                "dead_letter_entries": 3,
                "dead_letter_events": 12,
                "last_failure_at": now_ms - 300_000,
                "last_failure_code": 400,
                "last_failure_reason": "400: json: unknown field \"trace_id\"",
            },
        })));
        assert!(
            out.contains("3 batch(es) / 12 event(s) queued"),
            "queue depth missing: {}",
            out
        );
        assert!(
            out.contains("NOT delivered yet"),
            "backlog not called out as undelivered: {}",
            out
        );
        assert!(
            out.contains("5m ago") && out.contains("HTTP 400") && out.contains("unknown field"),
            "failure attribution missing: {}",
            out
        );
        assert!(
            out.contains("version skew") && out.contains("Upgrade the Control Panel"),
            "400 skew hint missing: {}",
            out
        );
        assert!(
            out.contains("aikey proxy replay-dead-letter"),
            "recovery command missing: {}",
            out
        );
    }

    /// Non-400 backlog gets the generic cause hint, not the skew story.
    #[test]
    fn non_400_backlog_gets_generic_next_step() {
        let out = plain(Some(&json!({
            "reporter": {"last_upload_status": "error"},
            "compliance": {
                "dead_letter_entries": 1,
                "dead_letter_events": 1,
                "last_failure_reason": "dial tcp 127.0.0.1:1: connection refused",
            },
        })));
        assert!(
            out.contains("connection refused") && out.contains("aikey proxy replay-dead-letter"),
            "generic hint missing: {}",
            out
        );
        assert!(!out.contains("version skew"), "wrong hint: {}", out);
    }

    /// Shape 3 — proxy older than the compliance queue reporting. The absent
    /// field must render as UNAVAILABLE. A `0` here is the exact failure mode
    /// this whole change exists to remove: it reads as healthy while the box is
    /// un-monitored.
    #[test]
    fn old_proxy_without_compliance_field_says_unavailable_not_zero() {
        let out = plain(Some(&json!({
            "source_id": "src-1",
            "allocated_seq": 10,
            "wal_files": 1,
            "dead_letter_count": 0,
            "reporter": {"last_upload_status": "ok"},
        })));
        assert!(
            out.contains("not reported by this proxy (older build)"),
            "missing-section wording wrong: {}",
            out
        );
        assert!(
            out.contains("INVISIBLE") && out.contains("aikey proxy restart"),
            "blind-spot warning / next step missing: {}",
            out
        );
        assert!(
            !out.contains("nothing queued"),
            "absent section rendered as healthy: {}",
            out
        );
    }

    /// A drained queue that failed earlier is healthy — report the history,
    /// do not keep alarming.
    #[test]
    fn drained_queue_after_failure_reads_healthy_with_history() {
        let out = plain(Some(&json!({
            "reporter": {"last_upload_status": "ok"},
            "compliance": {
                "dead_letter_entries": 0,
                "dead_letter_events": 0,
                "last_failure_code": 503,
                "last_failure_reason": "503 service unavailable",
            },
        })));
        assert!(
            out.contains("nothing queued (last failure HTTP 503") && out.contains("since drained"),
            "recovered wording wrong: {}",
            out
        );
    }

    /// The proxy being down must not be confused with "compliance is fine".
    #[test]
    fn unreachable_proxy_reports_no_compliance_verdict() {
        let out = plain(None);
        assert!(out.contains("not reachable"), "{}", out);
        assert!(!out.contains("Compliance upload"), "{}", out);
    }

    /// The proxy's reason is "<status>: <body>"; rendering it under our own
    /// "HTTP <code>" must not stutter "HTTP 400: 400: {...}".
    #[test]
    fn duplicated_status_prefix_is_collapsed_without_losing_the_body() {
        let rendered = render_compliance_failure(&json!({
            "last_failure_code": 400,
            "last_failure_reason": "400: json: unknown field \"trace_id\"",
        }))
        .expect("failure present");
        assert_eq!(rendered, "HTTP 400: json: unknown field \"trace_id\"");
    }

    #[test]
    fn failure_reason_is_truncated() {
        let long = "x".repeat(400);
        let rendered = render_compliance_failure(&json!({
            "last_failure_code": 400,
            "last_failure_reason": long,
        }))
        .expect("failure present");
        assert!(
            rendered.chars().count() < 200,
            "reason not truncated: {} chars",
            rendered.chars().count()
        );
    }
}

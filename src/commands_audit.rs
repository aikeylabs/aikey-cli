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

use std::time::Duration;

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
    let Some(l) = local else {
        println!("\n  Local client (proxy): not reachable (run `aikey proxy status`).");
        return;
    };
    let rep = &l["reporter"];
    println!(
        "\n  Local client (proxy): allocated={} WAL-files={} dead-letter={} last-upload={}",
        l["allocated_seq"].as_i64().unwrap_or(0),
        l["wal_files"].as_i64().unwrap_or(0),
        l["dead_letter_count"].as_i64().unwrap_or(0),
        rep["last_upload_status"].as_str().unwrap_or("n/a"),
    );
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

//! Command handlers for `aikey trust verify | status | history | sync`.

use crate::cli::SyncTarget;
use crate::commands_trust::client::{StatusSummary, TrustClient, VerifyDetail};
use crate::storage::open_connection_readonly;
use colored::Colorize;
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

/// Polling interval for `aikey trust verify` (default wait).
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Hard cap on wait time. Real cascade ~30s; 5-min guard against runaway.
const POLL_TIMEOUT: Duration = Duration::from_secs(300);

// ───────────────────────────────────────────────────────────────────────────
// verify
// ───────────────────────────────────────────────────────────────────────────

pub(crate) fn handle_verify(
    alias: &str,
    force: bool,
    no_wait: bool,
    json: bool,
) -> Result<(), String> {
    let (provider, model) = resolve_provider_model(alias)?;

    let client = TrustClient::new();
    let accept = client
        .post_verify(alias, &provider, &model, force)
        .map_err(|e| format_ureq_err(&client, e, "trust-local POST /v1/verify"))?;

    if no_wait {
        if json {
            let v = serde_json::json!({
                "verify_id": accept.verify_id,
                "status": accept.status,
                "triggered_at": accept.triggered_at,
                "alias": alias,
                "provider_id": provider,
                "model": model,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            );
        } else {
            println!(
                "verify started: {} (alias={}, provider={}, model={})",
                accept.verify_id, alias, provider, model
            );
            println!("check progress: aikey trust history {}", alias);
        }
        return Ok(());
    }

    let final_detail = poll_until_done(&client, &accept.verify_id, alias, json)?;

    if json {
        let v = final_detail.scoring_detail.unwrap_or(serde_json::json!({}));
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
    } else {
        print_verify_result(&final_detail);
    }

    match final_detail.status.as_str() {
        "pass" => Ok(()),
        "fail" => Err("verify FAILED — model appears different from expected".to_string()),
        _ => Err("verify INCONCLUSIVE — see error_message above".to_string()),
    }
}

fn poll_until_done(
    client: &TrustClient,
    verify_id: &str,
    alias: &str,
    json: bool,
) -> Result<VerifyDetail, String> {
    let start = Instant::now();
    let mut last_n_done: i64 = -1;
    let mut stderr = std::io::stderr();

    loop {
        if start.elapsed() > POLL_TIMEOUT {
            return Err(format!(
                "verify polling timed out after {}s. Check: aikey trust history {}",
                POLL_TIMEOUT.as_secs(),
                alias,
            ));
        }

        let detail = client
            .get_verify(verify_id)
            .map_err(|e| format_ureq_err(client, e, "trust-local GET /v1/verify/{id}"))?;

        if !json {
            if let Some(prog) = &detail.progress {
                if prog.n_done != last_n_done {
                    let qid = prog.current_qid.as_deref().unwrap_or("…");
                    let _ = write!(
                        stderr,
                        "\rVerifying {}: Q{}/{} {:<40}",
                        alias, prog.n_done, prog.n_total, qid,
                    );
                    let _ = stderr.flush();
                    last_n_done = prog.n_done;
                }
            }
        }

        if detail.status != "running" {
            if !json {
                let _ = write!(stderr, "\r{:80}\r", " ");
                let _ = stderr.flush();
            }
            return Ok(detail);
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn print_verify_result(d: &VerifyDetail) {
    let icon = match d.status.as_str() {
        "pass" => crate::symbols::CHECK.s().green().bold().to_string(),
        "fail" => crate::symbols::CROSS.s().red().bold().to_string(),
        _ => "?".yellow().bold().to_string(),
    };
    let n_pass = d
        .scoring_detail
        .as_ref()
        .and_then(|v| v.get("n_pass"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let n_total = d
        .scoring_detail
        .as_ref()
        .and_then(|v| v.get("n_total"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let duration_str = d
        .duration_ms
        .map(|ms| format!("{}ms", ms))
        .unwrap_or_else(|| "?".to_string());

    println!(
        "{} {} — {}/{} questions match ({}, model={})",
        icon,
        d.status.to_uppercase(),
        n_pass,
        n_total,
        duration_str,
        d.model,
    );

    if let Some(err) = &d.error_message {
        eprintln!("  detail: {}", err);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// status
// ───────────────────────────────────────────────────────────────────────────

pub(crate) fn handle_status(alias: Option<&str>, json: bool) -> Result<(), String> {
    let client = TrustClient::new();

    match alias {
        None => {
            let list = client
                .list_status()
                .map_err(|e| format_ureq_err(&client, e, "trust-local GET /v1/status"))?;
            if json {
                let v = serde_json::json!({
                    "items": list.items.iter().map(summary_to_json).collect::<Vec<_>>(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
            } else if list.items.is_empty() {
                println!("(no aliases observed yet — run aikey trust verify <alias> to populate)");
            } else {
                print_status_table(&list.items);
            }
        }
        Some(name) => {
            let detail = client
                .get_status(name)
                .map_err(|e| format_ureq_err(&client, e, "trust-local GET /v1/status/{alias}"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary_to_json(&detail))
                        .map_err(|e| e.to_string())?
                );
            } else {
                print_status_detail(&detail);
            }
        }
    }
    Ok(())
}

fn summary_to_json(s: &StatusSummary) -> serde_json::Value {
    serde_json::json!({
        "alias": s.alias_name,
        "provider": s.provider_id,
        "model": s.model,
        "updated_at": s.updated_at,
        "last_verified_at": s.last_verified_at,
        "last_verify_result": s.last_verify_result,
        "s_combined": s.s_combined,
        "anomaly_suggested": s.anomaly_suggested,
    })
}

fn print_status_table(items: &[StatusSummary]) {
    println!(
        "{:<24} {:<14} {:<28} {:>8} {:<14} {}",
        "alias", "provider", "model", "score", "verdict", "verified",
    );
    for s in items {
        let score = s
            .s_combined
            .map(|v| format!("{:.1}", v))
            .unwrap_or_else(|| "—".to_string());
        let verdict = colorize_verdict(&s.last_verify_result);
        let verified = s
            .last_verified_at
            .map(format_relative)
            .unwrap_or_else(|| "never".to_string());
        let badge = if s.anomaly_suggested {
            format!(" {}", crate::symbols::WARN.s())
        } else {
            String::new()
        };
        println!(
            "{:<24} {:<14} {:<28} {:>8} {:<14} {}{}",
            s.alias_name, s.provider_id, s.model, score, verdict, verified, badge,
        );
    }
}

fn print_status_detail(s: &StatusSummary) {
    println!("alias:      {}", s.alias_name);
    println!("provider:   {}", s.provider_id);
    println!("model:      {}", s.model);
    println!(
        "score:      {}",
        s.s_combined
            .map(|v| format!("{:.1} / 100", v))
            .unwrap_or_else(|| "—".to_string())
    );
    println!("verdict:    {}", colorize_verdict(&s.last_verify_result));
    if let Some(ts) = s.last_verified_at {
        println!("verified:   {}", format_relative(ts));
    }
    if s.anomaly_suggested {
        println!(
            "\n{}",
            format!("{} ANOMALY SUGGESTED", crate::symbols::WARN.s())
                .yellow()
                .bold()
        );
        println!("  D1/D2 hits crossed threshold in the last 24h.");
        println!("  Recommended: aikey trust verify {}", s.alias_name);
    }

    if !s.cascade_history.is_empty() {
        println!("\nRecent verify runs:");
        for h in s.cascade_history.iter().take(5) {
            let v = colorize_verdict(&h.status);
            let dur = h
                .duration_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "?".to_string());
            println!("  {} {} ({})", format_relative(h.triggered_at), v, dur);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// history
// ───────────────────────────────────────────────────────────────────────────

pub(crate) fn handle_history(alias: &str, json: bool) -> Result<(), String> {
    let client = TrustClient::new();
    let detail = client
        .get_status(alias)
        .map_err(|e| format_ureq_err(&client, e, "trust-local GET /v1/status/{alias}"))?;

    if json {
        let v = serde_json::json!({
            "alias": detail.alias_name,
            "history": detail.cascade_history.iter().map(|h| serde_json::json!({
                "verify_id": h.verify_id,
                "triggered_at": h.triggered_at,
                "completed_at": h.completed_at,
                "status": h.status,
                "duration_ms": h.duration_ms,
                "error_message": h.error_message,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
    } else {
        if detail.cascade_history.is_empty() {
            println!(
                "(no verify history for {} — run: aikey trust verify {})",
                alias, alias
            );
            return Ok(());
        }
        println!("Verify history for {}:", alias);
        for h in &detail.cascade_history {
            let v = colorize_verdict(&h.status);
            let dur = h
                .duration_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "?".to_string());
            let ts = format_relative(h.triggered_at);
            println!("  {} {} ({})", ts, v, dur);
            if let Some(err) = &h.error_message {
                println!("    error: {}", err);
            }
        }
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// sync
// ───────────────────────────────────────────────────────────────────────────

pub(crate) fn handle_sync(target: &SyncTarget, json: bool) -> Result<(), String> {
    let client = TrustClient::new();
    let mut results = Vec::new();

    if matches!(target, SyncTarget::Baseline | SyncTarget::Both) {
        let r = client
            .post_sync_baseline()
            .map_err(|e| format_ureq_err(&client, e, "trust-local POST /v1/sync/baseline"))?;
        results.push(("baseline", r));
    }
    if matches!(target, SyncTarget::Questions | SyncTarget::Both) {
        let r = client
            .post_sync_questions()
            .map_err(|e| format_ureq_err(&client, e, "trust-local POST /v1/sync/questions"))?;
        results.push(("questions", r));
    }

    if json {
        let summary = results
            .iter()
            .map(|(k, r)| {
                serde_json::json!({
                    "kind": k,
                    "last_attempt_at": r.state.last_attempt_at,
                    "last_success_at": r.state.last_success_at,
                    "last_error": r.state.last_error,
                    "per_target": r.results.iter().map(|t| serde_json::json!({
                        "status": t.status,
                        "version": t.version,
                        "error_message": t.error_message,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "results": summary }))
                .map_err(|e| e.to_string())?
        );
    } else {
        for (kind, r) in &results {
            let n_updated = r.results.iter().filter(|t| t.status == "updated").count();
            let n_nochange = r.results.iter().filter(|t| t.status == "no_change").count();
            let n_failed = r.results.iter().filter(|t| t.status == "failed").count();
            println!(
                "  {}: {} updated, {} no_change, {} failed",
                kind, n_updated, n_nochange, n_failed,
            );
            if let Some(err) = &r.state.last_error {
                if !err.is_empty() && err != "null" {
                    eprintln!("    last_error: {}", err);
                }
            }
        }
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// refresh
// ───────────────────────────────────────────────────────────────────────────

pub(crate) fn handle_refresh(alias: Option<&str>, json: bool) -> Result<(), String> {
    let client = TrustClient::new();
    // If an alias is provided we resolve its provider/model via the
    // same vault-priority chain `aikey trust verify` uses. Omitted →
    // server-side sweep.
    let target = match alias {
        Some(a) => {
            let (provider, model) = resolve_provider_model(a)?;
            Some((a.to_string(), provider, model))
        }
        None => None,
    };
    let body = target
        .as_ref()
        .map(|(a, p, m)| (a.as_str(), p.as_str(), m.as_str()));
    let resp = client
        .post_aggregate(body)
        .map_err(|e| format_ureq_err(&client, e, "trust-local POST /v1/aggregate"))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "written": resp.written,
                "items": resp.items.iter().map(|r| serde_json::json!({
                    "alias_name": r.alias_name,
                    "provider_id": r.provider_id,
                    "model": r.model,
                    "s_l1": r.s_l1,
                    "anomaly_suggested": r.anomaly_suggested,
                    "signals_summary": r.signals_summary,
                })).collect::<Vec<_>>(),
            }))
            .map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "refreshed {} alias(es) from local observations",
            resp.written
        );
        for r in &resp.items {
            // Compact one-line per row: alias  s_l1=N  [anomaly]  hits=...
            let l1 = r
                .s_l1
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".to_string());
            // signals_summary may be an empty {} (no observations in
            // window) — print "no observations in window" so the
            // user knows the aggregator actually ran but found nothing.
            let hits_blurb = r
                .signals_summary
                .get("hits")
                .and_then(|h| h.as_object())
                .map(|map| {
                    if map.is_empty() {
                        "no observations in window".to_string()
                    } else {
                        let mut parts: Vec<String> =
                            map.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
                        parts.sort();
                        format!("hits={}", parts.join(","))
                    }
                })
                .unwrap_or_else(|| "no observations in window".to_string());
            let anomaly_tag = if r.anomaly_suggested {
                format!("  {}ANOMALY", crate::symbols::WARN.s())
            } else {
                String::new()
            };
            println!(
                "  {} ({}/{}) s_l1={} {}{}",
                r.alias_name, r.provider_id, r.model, l1, hits_blurb, anomaly_tag,
            );
        }
    }
    Ok(())
}

// Service start/stop/restart (`aikey.trust-local` launchd / systemd
// label) lives in commands_service::trust_local, not here — the
// trust namespace is API-talking (verify/status/history/sync/refresh)
// while service control is OS-process management. They share no helpers.

// ───────────────────────────────────────────────────────────────────────────
// shared helpers
// ───────────────────────────────────────────────────────────────────────────

/// Resolve `(provider, model)` for an alias by scanning vault in priority
/// order: personal API key (`entries`) first, then OAuth account
/// (`provider_accounts`). OAuth aliases are looked up against both
/// `local_alias` (user-renamed label) and `display_identity` (original
/// email / external_id from the OAuth provider) so verifying a Pro/Max
/// subscription account works whether the user typed the email or the
/// renamed label.
///
/// The provider-code → canonical mapping covers OAuth provider codes
/// (`claude` / `codex` / `kimi_code`) on top of the API-key codes
/// (`anthropic` / `openai` / `kimi`). Both map to the same default model
/// because the cascade question bank is keyed on canonical provider,
/// not on credential type.
fn resolve_provider_model(alias: &str) -> Result<(String, String), String> {
    let conn = open_connection_readonly()?;

    // Personal API key first — entries.provider_code is the canonical
    // provider id we want.
    let api_key_row: Option<String> = conn
        .query_row(
            "SELECT provider_code FROM entries WHERE alias = ?1",
            rusqlite::params![alias],
            |r| r.get::<_, String>(0),
        )
        .ok();

    // OAuth fallback — provider_accounts.provider is the OAuth provider
    // code (claude / codex / kimi_code). Look up by either the
    // user-renamed `local_alias` or the immutable `display_identity`
    // (email / external_id); same alias may be either depending on
    // whether the user ran `aikey rename`.
    let oauth_row: Option<String> = if api_key_row.is_some() {
        None
    } else {
        conn.query_row(
            "SELECT provider FROM provider_accounts \
             WHERE local_alias = ?1 OR display_identity = ?1",
            rusqlite::params![alias],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };

    let provider = api_key_row.or(oauth_row).ok_or_else(|| {
        format!(
            "alias '{}' not found in vault. Run `aikey list` to see available aliases.",
            alias
        )
    })?;

    // Map OAuth provider codes onto the same canonical provider as their
    // API-key sibling: `claude` (Claude Pro/Max OAuth) → anthropic;
    // `codex` (ChatGPT OAuth) → openai; `kimi_code` → kimi. The cascade
    // question bank is keyed on the canonical id, not the auth method.
    let (canonical_provider, model) = match provider.as_str() {
        "anthropic" | "claude" => ("anthropic", "claude-opus-4-7"),
        "openai" | "codex" => ("openai", "gpt-4o"),
        "kimi" | "kimi_code" => ("kimi", "kimi-k2-instruct-0905"),
        other => {
            return Err(format!(
                "no default model for provider '{}' (M4: add --model flag if you need this)",
                other
            ))
        }
    };

    Ok((canonical_provider.to_string(), model.to_string()))
}

/// Translate a ureq error into an actionable user-facing message.
fn format_ureq_err(client: &TrustClient, e: ureq::Error, ctx: &str) -> String {
    match e {
        ureq::Error::Status(429, resp) => {
            let body = resp.into_string().unwrap_or_default();
            format!("rate limited: {}\n(pass --force to bypass)", body)
        }
        ureq::Error::Status(404, resp) => {
            format!("not found: {}", resp.into_string().unwrap_or_default())
        }
        ureq::Error::Status(code, resp) => format!(
            "trust-local error ({}): {}",
            code,
            resp.into_string().unwrap_or_default()
        ),
        ureq::Error::Transport(t) => {
            format!("{}\n{}\n(transport: {})", ctx, client.unreachable_hint(), t)
        }
    }
}

fn colorize_verdict(s: &str) -> String {
    match s {
        "pass" => s.green().bold().to_string(),
        "fail" => s.red().bold().to_string(),
        "inconclusive" => s.yellow().bold().to_string(),
        "running" => s.blue().bold().to_string(),
        _ => s.to_string(),
    }
}

fn format_relative(unix_ts: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let diff = now - unix_ts;
    if diff < 60 {
        format!("{}s ago", diff)
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

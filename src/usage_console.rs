//! Today's usage, read from the local console (aikey-local-server).
//!
//! 🔴 WHY THE CONSOLE AND NOT THE PROXY'S WAL (decision 2026-08-16).
//!
//! Both can answer "how much have I used". They are not equivalent:
//!
//!   - The WAL is what the proxy writes as it forwards. It is always present
//!     and needs nothing else running — but it holds raw token counts only.
//!     There is no price table on this machine, so a WAL reader can never
//!     show money.
//!   - The console's usage facade runs the query-service in-process against
//!     the local collector→DWD tables. It reports `cost_usd`, and it is the
//!     same source the console's own charts use.
//!
//! The user chose the console so that the tray and the console can never
//! disagree about a number the user can see in both places. The cost of that
//! choice is stated plainly rather than hidden: when the console is not
//! running, usage is UNAVAILABLE here, and this module says so instead of
//! reporting zero. "We cannot tell you" and "you used nothing" are different
//! facts and must not render the same.
//!
//! Two further limits, both inherited from the facade and both surfaced:
//!   - `cost_usd` covers priced rows only (USD-priced providers). A provider
//!     with no price data contributes tokens but no money — a real 0, not a
//!     missing value.
//!   - The query needs an account id, so a machine that has never signed in
//!     has no usage to show.

use serde::Deserialize;

/// One hour of today, as the console buckets it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HourPoint {
    /// Hour of day 0-23 in `time_zone`.
    pub hour: i64,
    pub tokens: i64,
    pub requests: i64,
    pub cost_usd: f64,
}

/// What the console reports for today.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RouteTotal {
    /// Client-route slot (`kimi`, `anthropic`) — the SAME axis `routes[].route`
    /// and `candidates[].client_routes` use, so the panel can join by string
    /// equality. Provider codes are aggregated INTO their route here
    /// (kimi_code + moonshot both land in `kimi`) via client_route_for_binding
    /// — the one existing family mapping, not a second copy.
    pub route: String,
    pub tokens: i64,
    pub requests: i64,
    pub cost_usd: f64,
    /// Hourly series for THIS route (variant B). Empty when the console
    /// predates group_by=provider — the panel then falls back to variant A
    /// (receded machine chart) with no special-casing.
    pub series: Vec<HourPoint>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ConsoleUsage {
    /// False when the figure could not be obtained at all. Callers must render
    /// this differently from a zero total.
    pub available: bool,
    /// Why it is unavailable, in words a non-technical reader can act on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// See `unavailable_codes`. Additive; absent on success.
    pub unavailable_code: Option<String>,
    pub total_tokens: i64,
    pub requests: i64,
    /// USD across priced rows only; providers without price data add nothing.
    pub cost_usd: f64,
    /// The zone the hours are bucketed in, so the axis can say what it means.
    pub time_zone: String,
    /// Today's totals per client route — the data behind the panel's
    /// route↔usage linkage (2026-08-18, variant A). Empty when the by-app
    /// endpoint is unavailable; the linkage then simply does not engage,
    /// which beats blocking the headline totals on a second fetch.
    pub by_route: Vec<RouteTotal>,
    pub series: Vec<HourPoint>,
}

impl ConsoleUsage {
    fn unavailable(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            available: false,
            unavailable_code: Some(code.to_string()),
            unavailable_reason: Some(reason.into()),
            ..Default::default()
        }
    }
}

/// Machine-readable reasons usage can be unavailable (UPPER_SNAKE_CASE per the
/// logging conventions' error-code rule). The VIEW decides how to present each
/// one — the strings in `unavailable_reason` are terminal-facing and consumers
/// like the tray panel must never string-match them (2026-08-19: the panel
/// wants app-appropriate copy for the signed-out case, keyed on THIS).
pub mod unavailable_codes {
    pub const NOT_SIGNED_IN: &str = "NOT_SIGNED_IN";
    pub const CONSOLE_NOT_INSTALLED: &str = "CONSOLE_NOT_INSTALLED";
    pub const CONSOLE_UNREACHABLE: &str = "CONSOLE_UNREACHABLE";
    pub const USAGE_PARSE_ERROR: &str = "USAGE_PARSE_ERROR";
}

/// The facade's wire shape for `/v1/usage/personal/hourly`.
#[derive(Debug, Deserialize)]
struct HourRow {
    hour: i64,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    request_count: i64,
    /// Absent on servers older than rc.8; absent means "not reported", which
    /// we render as zero money rather than refusing the whole row.
    #[serde(default)]
    cost_usd: f64,
}

/// Resolve the IANA zone to bucket hours in.
///
/// The console's own charts send an explicit zone, so the tray must send the
/// same one or the two will disagree about which hour a request landed in.
/// `display.time_zone` is the CLI's existing preference for exactly this, and
/// `auto` follows the machine.
fn display_zone() -> Option<String> {
    let pref = crate::time_zone::preference();
    if pref != "auto" {
        return Some(pref);
    }
    system_zone()
}

/// Best-effort IANA zone for the machine.
///
/// Unix keeps `/etc/localtime` as a symlink into the zoneinfo tree, so the
/// tail of that path IS the zone name. There is no equivalent one-liner on
/// Windows, and rather than guess we return None — the caller then omits the
/// parameter and the server buckets in UTC, which is at least a zone we can
/// name in the UI instead of silently mislabelling local hours.
#[cfg(unix)]
fn system_zone() -> Option<String> {
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let path = target.to_string_lossy();
    let idx = path.find("zoneinfo/")?;
    let zone = &path[idx + "zoneinfo/".len()..];
    if zone.is_empty() {
        return None;
    }
    Some(zone.to_string())
}

#[cfg(not(unix))]
fn system_zone() -> Option<String> {
    None
}

/// Fetch today's hourly usage from the local console.
pub fn today_hourly() -> ConsoleUsage {
    let account = match crate::storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => {
            return ConsoleUsage::unavailable(
                unavailable_codes::NOT_SIGNED_IN,
                "not signed in — run `aikey account login` to see usage",
            )
        }
    };

    // A machine with no local-server at all is a different failure from one
    // whose console is merely stopped, and the user needs to be told which.
    let port = match crate::local_server_probe::read_local_server_port_or_default() {
        Ok(p) => p,
        Err(e) => {
            return ConsoleUsage::unavailable(
                unavailable_codes::CONSOLE_NOT_INSTALLED,
                format!("no local console is installed on this machine ({e})"),
            )
        }
    };
    let zone = display_zone();
    // scope=all — every identity on THIS machine (2026-08-20): personal keys,
    // team keys and OAuth all report under different org/account tags, and the
    // desktop app's headline is the machine's total, not one slice of it. The
    // local-server honours it only because a personal DB is one human's data;
    // a team deployment ignores the parameter entirely.
    //
    // 🔴 The Personal WEB deliberately does NOT send it (用户 2026-08-20:
    // "不要影响 Personal web 端") — same endpoint, unchanged answer there.
    let mut url = format!(
        "http://127.0.0.1:{}/api/user/usage/personal/hourly?scope=all&account_id={}",
        port, account.account_id
    );
    if let Some(z) = &zone {
        url.push_str("&tz=");
        url.push_str(z);
    }

    // 2 seconds: this runs behind `aikey status --json --usage`, which the
    // tray polls. A console that is wedged must not wedge the tray with it.
    let body = match crate::local_server_probe::ureq_get_with_timeout(&url, 2) {
        Ok(b) => b,
        Err(e) => {
            return ConsoleUsage::unavailable(
                unavailable_codes::CONSOLE_UNREACHABLE,
                format!("the local console is not answering on port {port} ({e}) — usage is shown by the console, so start it to see it here"),
            )
        }
    };

    let rows: Vec<HourRow> = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            // A parse failure is reported, never smoothed into "no usage" —
            // the two look identical on screen and mean opposite things.
            return ConsoleUsage::unavailable(
                unavailable_codes::USAGE_PARSE_ERROR,
                format!("could not read the console's usage reply: {e}"),
            );
        }
    };

    let mut out = ConsoleUsage {
        available: true,
        time_zone: zone.clone().unwrap_or_else(|| "UTC".to_string()),
        ..Default::default()
    };
    for r in rows {
        out.total_tokens += r.total_tokens;
        out.requests += r.request_count;
        out.cost_usd += r.cost_usd;
        out.series.push(HourPoint {
            hour: r.hour,
            tokens: r.total_tokens,
            requests: r.request_count,
            cost_usd: r.cost_usd,
        });
    }
    out.series.sort_by_key(|p| p.hour);

    // Per-route data for the panel's route↔usage linkage — ONE extra call:
    // the hourly endpoint with group_by=provider (additive param, 2026-08-18)
    // returns (hour, provider) rows, from which both the per-route totals AND
    // the per-route hourly series (variant B) are derived. Provider rows are
    // folded into their CLIENT ROUTE — the axis the panel joins on — through
    // the registry's one family mapping (kimi_code + moonshot → kimi), never
    // a second copy of it.
    //
    // Best-effort by design: a console predating group_by=provider returns
    // ungrouped rows (provider_code absent), which fold into a single ""
    // route that is dropped below — by_route stays empty, the panel shows
    // machine totals only, and nothing here can take the headline down.
    let mut grouped_url = format!(
        "http://127.0.0.1:{}/api/user/usage/personal/hourly?scope=all&account_id={}&group_by=provider",
        port, account.account_id
    );
    if let Some(z) = &zone {
        grouped_url.push_str("&tz=");
        grouped_url.push_str(z);
    }
    if let Ok(body) = crate::local_server_probe::ureq_get_with_timeout(&grouped_url, 2) {
        #[derive(serde::Deserialize)]
        struct GroupedRow {
            hour: i64,
            #[serde(default)]
            provider_code: String,
            total_tokens: i64,
            request_count: i64,
            cost_usd: f64,
        }
        if let Ok(rows) = serde_json::from_str::<Vec<GroupedRow>>(&body) {
            let mut acc: std::collections::BTreeMap<String, RouteTotal> =
                std::collections::BTreeMap::new();
            for r in rows {
                if r.provider_code.is_empty() {
                    continue; // ungrouped console (or pre-tagging row) — no axis to join on
                }
                let canonical =
                    crate::commands_account::oauth_provider_to_canonical(&r.provider_code);
                let route =
                    crate::provider_registry::client_route_for_binding(canonical, "").to_string();
                let e = acc.entry(route.clone()).or_insert_with(|| RouteTotal {
                    route,
                    tokens: 0,
                    requests: 0,
                    cost_usd: 0.0,
                    series: Vec::new(),
                });
                e.tokens += r.total_tokens;
                e.requests += r.request_count;
                e.cost_usd += r.cost_usd;
                // Two providers of one family can share an hour (kimi_code +
                // moonshot both at 10:00) — merge, don't append, or the chart
                // draws a sawtooth over duplicate hours.
                if let Some(pt) = e.series.iter_mut().find(|p| p.hour == r.hour) {
                    pt.tokens += r.total_tokens;
                    pt.requests += r.request_count;
                    pt.cost_usd += r.cost_usd;
                } else {
                    e.series.push(HourPoint {
                        hour: r.hour,
                        tokens: r.total_tokens,
                        requests: r.request_count,
                        cost_usd: r.cost_usd,
                    });
                }
            }
            for rt in acc.values_mut() {
                rt.series.sort_by_key(|p| p.hour);
            }
            out.by_route = acc.into_values().collect();
        }
    }
    out
}

#[cfg(test)]
mod scope_wiring_tests {
    /// Both usage fetches must carry scope=all: the headline totals and the
    /// per-route breakdown have to agree, and both are the MACHINE's usage
    /// (personal + team + OAuth), not the personal-key slice (2026-08-20).
    /// Source-level because the URLs are format! literals; a behavioural test
    /// would need the whole local-server.
    #[test]
    fn both_hourly_fetches_request_the_all_scope() {
        let src = include_str!("usage_console.rs");
        // Needle assembled at runtime: include_str! reads THIS file too, so a
        // literal needle would also match itself and inflate the count.
        let needle = format!("personal/hourly?{}=all", "scope");
        let n = src.matches(needle.as_str()).count();
        assert_eq!(
            n, 2,
            "expected BOTH hourly fetches (totals + group_by=provider) to send \
             scope=all, found {n}. A mismatch makes the headline and the \
             per-route chart disagree about the same day."
        );
    }
}

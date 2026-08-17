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
pub struct ConsoleUsage {
    /// False when the figure could not be obtained at all. Callers must render
    /// this differently from a zero total.
    pub available: bool,
    /// Why it is unavailable, in words a non-technical reader can act on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub total_tokens: i64,
    pub requests: i64,
    /// USD across priced rows only; providers without price data add nothing.
    pub cost_usd: f64,
    /// The zone the hours are bucketed in, so the axis can say what it means.
    pub time_zone: String,
    pub series: Vec<HourPoint>,
}

impl ConsoleUsage {
    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            unavailable_reason: Some(reason.into()),
            ..Default::default()
        }
    }
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
                "not signed in — run `aikey account login` to see usage",
            )
        }
    };

    // A machine with no local-server at all is a different failure from one
    // whose console is merely stopped, and the user needs to be told which.
    let port = match crate::local_server_probe::read_local_server_port_or_default() {
        Ok(p) => p,
        Err(e) => {
            return ConsoleUsage::unavailable(format!(
                "no local console is installed on this machine ({e})"
            ))
        }
    };
    let zone = display_zone();
    let mut url = format!(
        "http://127.0.0.1:{}/api/user/usage/personal/hourly?account_id={}",
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
            return ConsoleUsage::unavailable(format!(
                "the local console is not answering on port {port} ({e}) — usage is shown by the console, so start it to see it here"
            ))
        }
    };

    let rows: Vec<HourRow> = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            // A parse failure is reported, never smoothed into "no usage" —
            // the two look identical on screen and mean opposite things.
            return ConsoleUsage::unavailable(format!("could not read the console's usage reply: {e}"));
        }
    };

    let mut out = ConsoleUsage {
        available: true,
        time_zone: zone.unwrap_or_else(|| "UTC".to_string()),
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
    out
}

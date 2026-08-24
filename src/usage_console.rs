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
    /// Set when the TEAM half of this machine's usage could not be fetched, so
    /// the panel can say the figure is partial instead of presenting a
    /// local-only number as the total. Absent means "nothing was missing" —
    /// including on a machine with no team seat at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_slice_unavailable: Option<String>,
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
/// 🔴 Cross-platform since 2026-08-21. This used to read `/etc/localtime`'s
/// symlink tail on unix and return None everywhere else, with the reasoning
/// that naming no zone is better than guessing one. The cost of that on
/// Windows was not "no zone" but a WRONG-LOOKING CHART: the CLI omitted `tz`,
/// the query service bucketed in UTC, and the panel drew a 24-hour axis whose
/// labels the user naturally read as local time. Reported from a UTC-4 box —
/// wall clock 03:00, latest bar at "6" (UTC 06:00 = local 02:00).
///
/// `iana_time_zone` resolves the real IANA name on every platform the CLI
/// ships to (it is what chrono uses, and was already in the dependency tree),
/// so there is no longer a platform that has to fall back to UTC. None is
/// still returned when the host genuinely cannot say — the caller then omits
/// `tz` and the reply carries `time_zone: "UTC"`, which the panel labels
/// honestly rather than mislabelling local hours.
fn system_zone() -> Option<String> {
    let zone = iana_time_zone::get_timezone().ok()?;
    let zone = zone.trim();
    if zone.is_empty() {
        return None;
    }
    // Reject anything the SERVER cannot parse: it does `time.LoadLocation(tz)`
    // and falls back to UTC on error, which would silently reintroduce exactly
    // the mislabelled axis this function exists to prevent.
    if zone.parse::<chrono_tz::Tz>().is_err() {
        return None;
    }
    Some(zone.to_string())
}

/// Today's calendar date, resolved in `zone` (UTC when the zone is unknown).
///
/// 🔴 Resolve it in the SAME zone the URL declares via `&tz=` (bugfix
/// 2026-08-20). The two must agree or the request asks for "yesterday's date,
/// bucketed in today's zone" for the hours around local midnight.
///
/// WHY it is sent at all, rather than letting the server default: the hourly
/// endpoint shares its parameter parsing with the multi-day timeline
/// endpoints, whose default range starts 30 days back. Omitting `date` used to
/// select THAT day — a single day one month in the past — and the panel showed
/// 0 forever while the console (which always sends `date`) showed the real
/// number. The server now defaults to today as well, so this is belt AND
/// braces: the request states the day it means instead of relying on the other
/// side to guess the same one.
fn today_in(zone: Option<&str>) -> String {
    let now = chrono::Utc::now();
    match zone.and_then(|z| z.parse::<chrono_tz::Tz>().ok()) {
        Some(tz) => now.with_timezone(&tz).format("%Y-%m-%d").to_string(),
        // Unknown/absent zone: the server buckets in UTC in exactly this
        // case, so a UTC date keeps the two ends on the same day.
        None => now.format("%Y-%m-%d").to_string(),
    }
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
    let today = today_in(zone.as_deref());
    let mut url = format!(
        "http://127.0.0.1:{}/api/user/usage/personal/hourly?scope=all&account_id={}&date={}",
        port, account.account_id, today
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
        "http://127.0.0.1:{}/api/user/usage/personal/hourly?scope=all&account_id={}&date={}&group_by=provider",
        port, account.account_id, today
    );
    if let Some(z) = &zone {
        grouped_url.push_str("&tz=");
        grouped_url.push_str(z);
    }
    let mut acc: std::collections::BTreeMap<String, RouteTotal> = std::collections::BTreeMap::new();
    if let Ok(body) = crate::local_server_probe::ureq_get_with_timeout(&grouped_url, 2) {
        fold_grouped_rows(&mut acc, &body);
    }

    merge_team_slice(&mut out, &mut acc, port, &today, zone.as_deref());

    for rt in acc.values_mut() {
        rt.series.sort_by_key(|p| p.hour);
    }
    out.by_route = acc.into_values().collect();
    out
}

/// Folds `group_by=provider` hourly rows into per-CLIENT-ROUTE totals.
///
/// Extracted 2026-08-21 so the LOCAL and TEAM halves of the machine's usage
/// land in the SAME accumulator. Before that the team slice reached the
/// headline but not `by_route`, so the panel's route↔usage linkage showed
/// "openai 15136" next to a 109355 total — a breakdown that visibly does not
/// add up to its own headline.
fn fold_grouped_rows(acc: &mut std::collections::BTreeMap<String, RouteTotal>, body: &str) {
    #[derive(serde::Deserialize)]
    struct GroupedRow {
        hour: i64,
        #[serde(default)]
        provider_code: String,
        total_tokens: i64,
        request_count: i64,
        cost_usd: f64,
    }
    if let Ok(rows) = serde_json::from_str::<Vec<GroupedRow>>(body) {
        for r in rows {
            if r.provider_code.is_empty() {
                continue; // ungrouped console (or pre-tagging row) — no axis to join on
            }
            let canonical = crate::commands_account::oauth_provider_to_canonical(&r.provider_code);
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
    }
}

/// Folds the TEAM-server slice of today's usage into `out`.
///
/// 🔴 WHY A SECOND SOURCE AT ALL (2026-08-21). Usage on this machine is split
/// across two stores BY DESIGN
/// (20260510-personal-team-数据隔离与合并显示.md):
///
///   personal keys + personal OAuth → the LOCAL collector  (`/api/user/usage/…`)
///   team-issued keys + the OAuth ACCOUNT POOL → the TEAM server
///       (`/v1/usage/…`, which the local console forwards)
///
/// Constraint 1 of that design keeps personal traffic off the team server;
/// constraint 4 says team data is read straight from the team server rather
/// than mirrored locally. So a panel that reads only the local store is
/// structurally incapable of showing the user's team traffic — which on a
/// company machine is usually ALL of their Claude usage. Measured on the
/// Windows box: local said 15136 tokens (Codex only) while the team server
/// held 94219 tokens / 4 requests of anthropic the panel never mentioned.
///
/// 🔴 The query key is `seat_id`, NOT `account_id`. The team server keys
/// member usage by seat; asking it for `account_id=<platform account>` or
/// `org_id=personal` returns `[]` — a convincing "you used nothing" that is
/// simply the wrong question.
///
/// BEST-EFFORT, and deliberately so: this call leaves the machine (the console
/// forwards it to the team server). A slow or offline team server must never
/// blank the headline or wedge the tray's poll, so a failure here leaves the
/// local figures standing and only marks the team slice as missing. Losing the
/// team slice silently would be worse than not having it — the user would read
/// a partial number as the whole.
fn merge_team_slice(
    out: &mut ConsoleUsage,
    acc: &mut std::collections::BTreeMap<String, RouteTotal>,
    port: u16,
    today: &str,
    zone: Option<&str>,
) {
    let seat = match crate::storage::get_team_seat_id() {
        Ok(Some(s)) => s,
        // No seat = this machine is not a team member. Nothing to merge, and
        // nothing is missing — do NOT flag the slice as unavailable.
        Ok(None) => return,
        Err(e) => {
            out.team_slice_unavailable = Some(format!("could not read the local seat id ({e})"));
            return;
        }
    };

    // The console's gateway forwards /v1/usage/* to the team server. Same path
    // the web console's team usage page uses — no new endpoint, no new backend.
    let mut url = format!(
        "http://127.0.0.1:{}/v1/usage/personal/hourly?seat_id={}&date={}",
        port, seat, today
    );
    if let Some(z) = zone {
        url.push_str("&tz=");
        url.push_str(z);
    }

    // 3s, slightly longer than the local call's 2s: this one crosses the
    // network. Still short enough that a dead team server costs the tray one
    // poll interval, not a hang.
    let body = match crate::local_server_probe::ureq_get_with_timeout(&url, 3) {
        Ok(b) => b,
        Err(e) => {
            out.team_slice_unavailable =
                Some(format!("team usage is not reachable right now ({e})"));
            return;
        }
    };
    let rows: Vec<HourRow> = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            out.team_slice_unavailable = Some(format!("could not read the team usage reply ({e})"));
            return;
        }
    };

    for r in rows {
        out.total_tokens += r.total_tokens;
        out.requests += r.request_count;
        out.cost_usd += r.cost_usd;
        match out.series.iter_mut().find(|p| p.hour == r.hour) {
            Some(p) => {
                p.tokens += r.total_tokens;
                p.requests += r.request_count;
                p.cost_usd += r.cost_usd;
            }
            None => out.series.push(HourPoint {
                hour: r.hour,
                tokens: r.total_tokens,
                requests: r.request_count,
                cost_usd: r.cost_usd,
            }),
        }
    }
    out.series.sort_by_key(|p| p.hour);

    // Same grouped call the local half makes, so the team slice reaches
    // by_route too. Best-effort on top of best-effort: the headline already
    // has the team tokens by this point, so a failure here costs the linkage,
    // never the number.
    let mut grouped = format!(
        "http://127.0.0.1:{}/v1/usage/personal/hourly?seat_id={}&date={}&group_by=provider",
        port, seat, today
    );
    if let Some(z) = zone {
        grouped.push_str("&tz=");
        grouped.push_str(z);
    }
    if let Ok(gbody) = crate::local_server_probe::ureq_get_with_timeout(&grouped, 3) {
        fold_grouped_rows(acc, &gbody);
    }
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

    /// Both fetches must also NAME the day they mean (bugfix 2026-08-20).
    /// The hourly endpoint shares its parameter parsing with the multi-day
    /// timeline endpoints, whose default range starts 30 days back; a request
    /// that omits `date` selected that day and got an empty array, which the
    /// panel rendered as a perfectly convincing 0. The server-side default is
    /// fixed too — this keeps the request self-describing so the two ends
    /// cannot drift apart again.
    /// The panel must read BOTH halves of this machine's usage. Team-issued
    /// keys and the OAuth account pool report to the TEAM server, not the local
    /// collector, so a panel that only queries the local store structurally
    /// cannot show them — measured 2026-08-21 on the Windows box: local 15136
    /// (Codex only) while the team server held 94219 tokens of anthropic.
    ///
    /// 能红: delete the merge_team_slice call and the team leg disappears; the
    /// headline silently becomes the local slice presented as the total.
    #[test]
    fn team_slice_is_merged_into_the_headline() {
        let src = include_str!("usage_console.rs");
        // Runtime-assembled needles: include_str! reads THIS file, so literals
        // would match themselves.
        let call = format!("{}(&mut out,", "merge_team_slice");
        assert_eq!(
            src.matches(call.as_str()).count(),
            1,
            "today_hourly must fold the team-server slice into the figures it returns"
        );
        // Keyed by seat, not account: the team server answers [] for an
        // account_id, which reads on screen as "you used nothing".
        let seat_q = format!("hourly?{}=", "seat_id");
        assert!(
            src.contains(seat_q.as_str()),
            "the team query must be keyed by seat_id — account_id/org_id return [] there"
        );
    }

    /// A team slice that could not be fetched must be REPORTED, never folded
    /// away: a local-only number presented as the total is the failure mode
    /// this whole investigation started from.
    #[test]
    fn missing_team_slice_is_surfaced_not_swallowed() {
        // Whitespace-collapsed: rustfmt line-wraps these assignments, so a
        // needle matched against the raw source silently under-counts.
        let src: String = include_str!("usage_console.rs")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let field = format!("out.{}_slice_unavailable = Some(", "team");
        let n = src.matches(field.as_str()).count();
        assert!(
            n >= 3,
            "every failure path in merge_team_slice (seat read, fetch, parse) must set \
             team_slice_unavailable so the panel can say the figure is partial; found {n}"
        );
    }

    /// The hour axis must be labelled in the USER's zone, on every platform.
    ///
    /// Windows used to have no zone lookup at all, so the CLI omitted `tz`,
    /// the server bucketed in UTC, and the panel drew hours the user read as
    /// local time — reported from a UTC-4 box as "clock says 03:00, chart says
    /// 06:00". A platform-conditional zone lookup is therefore a defect, not a
    /// portability nicety.
    ///
    /// 能红: reintroduce a `#[cfg(...)]`-gated `system_zone` that returns None
    /// off-unix and this fails.
    #[test]
    fn zone_lookup_is_not_platform_conditional() {
        let src: String = include_str!("usage_console.rs")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let f = format!("fn {}() -> Option<String>", "system_zone");
        assert_eq!(
            src.matches(f.as_str()).count(),
            1,
            "system_zone must have ONE cross-platform implementation — a per-platform \
             variant is how Windows ended up with a UTC-labelled axis"
        );
        let crate_call = format!("{}::get_timezone()", "iana_time_zone");
        assert!(
            src.contains(crate_call.as_str()),
            "the zone must come from the cross-platform IANA lookup, not from a \
             hand-rolled per-OS probe"
        );
    }

    #[test]
    fn both_hourly_fetches_name_the_day() {
        let src = include_str!("usage_console.rs");
        // Same runtime-assembled needle trick as above: include_str! reads
        // THIS file, so a literal would match itself.
        let needle = format!("&{}=", "date");
        let n = src.matches(needle.as_str()).count();
        assert_eq!(
            n, 4,
            "expected ALL FOUR hourly fetches (local totals, local per-route, \
             team totals, team per-route) to pin an explicit date, found {n}. Without it the \
             server answers for the day 30 days ago and the panel reads 0."
        );
    }
}

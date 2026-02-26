//! Event Store for usage tracking
//!
//! Records run/exec invocations with provider, command, exit code,
//! duration, and secrets count for local analytics.

use crate::storage;
use rusqlite::params;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Event {
    pub id: i64,
    pub timestamp: i64,
    pub event_type: String,
    pub provider: Option<String>,
    pub alias: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<i64>,
    pub secrets_count: Option<i32>,
    pub error: Option<String>,
    pub project: Option<String>,
    pub env: Option<String>,
    pub profile: Option<String>,
    pub ok: bool,
    pub error_type: Option<String>,
}

pub struct EventBuilder {
    event_type: String,
    provider: Option<String>,
    alias: Option<String>,
    command: Option<String>,
    exit_code: Option<i32>,
    duration_ms: Option<i64>,
    secrets_count: Option<i32>,
    error: Option<String>,
    project: Option<String>,
    env: Option<String>,
    profile: Option<String>,
    ok: bool,
    error_type: Option<String>,
}

impl EventBuilder {
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            provider: None,
            alias: None,
            command: None,
            exit_code: None,
            duration_ms: None,
            secrets_count: None,
            error: None,
            project: None,
            env: None,
            profile: None,
            ok: false,
            error_type: None,
        }
    }

    pub fn provider(mut self, p: &str) -> Self { self.provider = Some(p.to_string()); self }
    #[allow(dead_code)]
    pub fn alias(mut self, a: &str) -> Self { self.alias = Some(a.to_string()); self }
    pub fn command(mut self, c: &str) -> Self { self.command = Some(c.to_string()); self }
    pub fn exit_code(mut self, code: i32) -> Self { self.exit_code = Some(code); self }
    pub fn duration_ms(mut self, ms: i64) -> Self { self.duration_ms = Some(ms); self }
    pub fn secrets_count(mut self, n: i32) -> Self { self.secrets_count = Some(n); self }
    #[allow(dead_code)]
    pub fn error(mut self, e: &str) -> Self { self.error = Some(e.to_string()); self }
    #[allow(dead_code)]
    pub fn project(mut self, p: &str) -> Self { self.project = Some(p.to_string()); self }
    #[allow(dead_code)]
    pub fn env(mut self, e: &str) -> Self { self.env = Some(e.to_string()); self }
    #[allow(dead_code)]
    pub fn profile(mut self, p: &str) -> Self { self.profile = Some(p.to_string()); self }
    pub fn ok(mut self, v: bool) -> Self { self.ok = v; self }
    #[allow(dead_code)]
    pub fn error_type(mut self, t: &str) -> Self { self.error_type = Some(t.to_string()); self }

    pub fn record(self) -> Result<(), String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs() as i64;

        let ok_int: i32 = if self.ok { 1 } else { 0 };

        let conn = storage::open_connection()?;
        conn.execute(
            "INSERT INTO events (timestamp, event_type, provider, alias, command, exit_code, duration_ms, secrets_count, error, project, env, profile, ok, error_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                timestamp,
                self.event_type,
                self.provider,
                self.alias,
                self.command,
                self.exit_code,
                self.duration_ms,
                self.secrets_count,
                self.error,
                self.project,
                self.env,
                self.profile,
                ok_int,
                self.error_type,
            ],
        )
        .map_err(|e| format!("Failed to insert event: {}", e))?;

        Ok(())
    }
}

/// Query recent events, newest first.
pub fn list_events(limit: u32) -> Result<Vec<Event>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, event_type, provider, alias, command, exit_code, duration_ms, secrets_count, error, project, env, profile, ok, error_type
             FROM events ORDER BY timestamp DESC LIMIT ?1",
        )
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params![limit], |row| {
            let ok_int: i32 = row.get(13).unwrap_or(0);
            Ok(Event {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                provider: row.get(3)?,
                alias: row.get(4)?,
                command: row.get(5)?,
                exit_code: row.get(6)?,
                duration_ms: row.get(7)?,
                secrets_count: row.get(8)?,
                error: row.get(9)?,
                project: row.get(10)?,
                env: row.get(11)?,
                profile: row.get(12)?,
                ok: ok_int != 0,
                error_type: row.get(14)?,
            })
        })
        .map_err(|e| format!("Failed to query events: {}", e))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to read events: {}", e))
}

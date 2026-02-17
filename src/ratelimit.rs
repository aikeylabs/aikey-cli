//! Rate Limiting Module
//!
//! Provides protection against brute-force password attacks by implementing
//! exponential backoff after failed authentication attempts.

use std::time::{SystemTime, UNIX_EPOCH};

/// Failed attempt tracking
#[derive(Debug)]
pub struct RateLimiter {
    failed_attempts: u32,
    last_attempt_time: u64,
    lockout_until: u64,
}

impl RateLimiter {
    /// Maximum failed attempts before lockout
    const MAX_ATTEMPTS: u32 = 3;

    /// Base lockout duration in seconds
    const BASE_LOCKOUT_SECS: u64 = 30;

    /// Load rate limiter state from storage
    pub fn load() -> Result<Self, String> {
        let conn = crate::storage::open_connection()?;

        // Try to get failed attempts count
        let failed_attempts: u32 = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'failed_attempts'",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                },
            )
            .unwrap_or(0);

        // Try to get last attempt time
        let last_attempt_time: u64 = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'last_attempt_time'",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                    ]))
                },
            )
            .unwrap_or(0);

        // Try to get lockout time
        let lockout_until: u64 = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'lockout_until'",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                    ]))
                },
            )
            .unwrap_or(0);

        Ok(RateLimiter {
            failed_attempts,
            last_attempt_time,
            lockout_until,
        })
    }

    /// Check if authentication is currently allowed
    pub fn check_allowed(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e))?
            .as_secs();

        if now < self.lockout_until {
            let remaining = self.lockout_until - now;
            return Err(format!(
                "Too many failed attempts. Please wait {} seconds before trying again.",
                remaining
            ));
        }

        Ok(())
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&mut self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e))?
            .as_secs();

        // Reset counter if last attempt was more than 1 hour ago
        if now - self.last_attempt_time > 3600 {
            self.failed_attempts = 0;
        }

        self.failed_attempts += 1;
        self.last_attempt_time = now;

        // Calculate exponential backoff
        if self.failed_attempts >= Self::MAX_ATTEMPTS {
            let backoff_multiplier = 2u64.pow(self.failed_attempts - Self::MAX_ATTEMPTS);
            let lockout_duration = Self::BASE_LOCKOUT_SECS * backoff_multiplier;
            self.lockout_until = now + lockout_duration;
        }

        self.save()?;
        Ok(())
    }

    /// Record a successful authentication (resets counter)
    pub fn record_success(&mut self) -> Result<(), String> {
        self.failed_attempts = 0;
        self.last_attempt_time = 0;
        self.lockout_until = 0;
        self.save()?;
        Ok(())
    }

    /// Save rate limiter state to storage
    fn save(&self) -> Result<(), String> {
        let conn = crate::storage::open_connection()?;

        // Save failed attempts
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('failed_attempts', ?)",
            [&self.failed_attempts.to_le_bytes()[..]],
        )
        .map_err(|e| format!("Failed to save failed_attempts: {}", e))?;

        // Save last attempt time
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('last_attempt_time', ?)",
            [&self.last_attempt_time.to_le_bytes()[..]],
        )
        .map_err(|e| format!("Failed to save last_attempt_time: {}", e))?;

        // Save lockout time
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('lockout_until', ?)",
            [&self.lockout_until.to_le_bytes()[..]],
        )
        .map_err(|e| format!("Failed to save lockout_until: {}", e))?;

        Ok(())
    }
}

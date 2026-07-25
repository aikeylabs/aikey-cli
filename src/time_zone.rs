//! Device display-time-zone preference shared by CLI presentation surfaces.
//! Wire timestamps and logs remain UTC; only user-visible absolute time changes.

use chrono::{TimeZone, Utc};
use chrono_tz::Tz;

const DISPLAY_TIME_ZONE_KEY: &str = "display.time_zone";

pub fn preference() -> String {
    match crate::storage::get_text_config(DISPLAY_TIME_ZONE_KEY) {
        None => "auto".to_string(),
        Some(value) if value.parse::<Tz>().is_ok() => value,
        Some(value) => {
            eprintln!(
                "[aikey] WARN: invalid display.time_zone '{}'; following the system time zone",
                value
            );
            "auto".to_string()
        }
    }
}

pub fn set_preference(value: &str) -> Result<String, String> {
    let clean = value.trim();
    if clean.eq_ignore_ascii_case("auto") || clean.is_empty() {
        crate::storage::delete_text_config(DISPLAY_TIME_ZONE_KEY)?;
        return Ok("auto".to_string());
    }
    clean.parse::<Tz>().map_err(|_| {
        format!(
            "Invalid IANA time zone '{}'. Try Asia/Shanghai for Beijing/China, or 'auto'.",
            clean
        )
    })?;
    crate::storage::try_set_text_config(DISPLAY_TIME_ZONE_KEY, clean)?;
    Ok(clean.to_string())
}

fn manual_zone() -> Option<Tz> {
    let value = crate::storage::get_text_config(DISPLAY_TIME_ZONE_KEY)?;
    match value.parse::<Tz>() {
        Ok(zone) => Some(zone),
        Err(_) => {
            eprintln!(
                "[aikey] WARN: invalid display.time_zone '{}'; following the system time zone",
                value
            );
            None
        }
    }
}

pub fn format_hm(unix_millis: i64) -> Option<String> {
    let zone = manual_zone()?;
    let utc = Utc.timestamp_millis_opt(unix_millis).single()?;
    Some(utc.with_timezone(&zone).format("%H:%M").to_string())
}

pub fn format_date(unix_secs: i64) -> Option<String> {
    let zone = manual_zone()?;
    let utc = Utc.timestamp_opt(unix_secs, 0).single()?;
    Some(utc.with_timezone(&zone).format("%Y-%m-%d").to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn beijing_uses_canonical_shanghai_zone() {
        let zone: chrono_tz::Tz = "Asia/Shanghai".parse().unwrap();
        let utc = chrono::TimeZone::timestamp_opt(&chrono::Utc, 0, 0)
            .single()
            .unwrap();
        assert_eq!(
            utc.with_timezone(&zone).format("%H:%M").to_string(),
            "08:00"
        );
        assert!("Asia/Beijing".parse::<chrono_tz::Tz>().is_err());
    }
}

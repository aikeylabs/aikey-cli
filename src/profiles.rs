use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub is_active: bool,
    pub created_at: i64,
}

/// List all profiles
pub fn list_profiles(conn: &Connection) -> Result<Vec<Profile>, String> {
    let mut stmt = conn
        .prepare("SELECT id, name, is_active, created_at FROM profiles ORDER BY name")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let profiles = stmt
        .query_map([], |row| {
            Ok(Profile {
                id: row.get(0)?,
                name: row.get(1)?,
                is_active: row.get::<_, i64>(2)? != 0,
                created_at: row.get(3)?,
            })
        })
        .map_err(|e| format!("Failed to query profiles: {}", e))?
        .collect::<SqlResult<Vec<Profile>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(profiles)
}

/// Get the active profile
pub fn get_active_profile(conn: &Connection) -> Result<Option<Profile>, String> {
    let result = conn
        .query_row(
            "SELECT id, name, is_active, created_at FROM profiles WHERE is_active = 1",
            [],
            |row| {
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    is_active: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("Failed to query active profile: {}", e))?;

    Ok(result)
}

/// Create a new profile
pub fn create_profile(conn: &Connection, name: &str) -> Result<Profile, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get current time: {}", e))?
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO profiles (name, is_active, created_at) VALUES (?, ?, ?)",
        params![name, 0, now],
    )
    .map_err(|e| format!("Failed to create profile: {}", e))?;

    Ok(Profile {
        id: conn.last_insert_rowid(),
        name: name.to_string(),
        is_active: false,
        created_at: now,
    })
}

/// Set a profile as active
pub fn set_active_profile(conn: &Connection, name: &str) -> Result<Profile, String> {
    // Deactivate all profiles
    conn.execute("UPDATE profiles SET is_active = 0", [])
        .map_err(|e| format!("Failed to deactivate profiles: {}", e))?;

    // Activate the specified profile
    conn.execute(
        "UPDATE profiles SET is_active = 1 WHERE name = ?",
        params![name],
    )
    .map_err(|e| format!("Failed to activate profile: {}", e))?;

    // Retrieve and return the activated profile
    conn.query_row(
        "SELECT id, name, is_active, created_at FROM profiles WHERE name = ?",
        params![name],
        |row| {
            Ok(Profile {
                id: row.get(0)?,
                name: row.get(1)?,
                is_active: row.get::<_, i64>(2)? != 0,
                created_at: row.get(3)?,
            })
        },
    )
    .map_err(|e| format!("Failed to retrieve profile: {}", e))
}

/// Delete a profile
pub fn delete_profile(conn: &Connection, name: &str) -> Result<(), String> {
    // Delete bindings first
    conn.execute(
        "DELETE FROM bindings WHERE profile_name = ?",
        params![name],
    )
    .map_err(|e| format!("Failed to delete bindings: {}", e))?;

    // Delete the profile
    conn.execute(
        "DELETE FROM profiles WHERE name = ?",
        params![name],
    )
    .map_err(|e| format!("Failed to delete profile: {}", e))?;

    Ok(())
}

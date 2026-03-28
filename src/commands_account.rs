//! `aikey account` and team key command handlers.
//!
//! Covers:
//!  - `aikey account login` / `aikey account status` / `aikey account logout`
//!  - `aikey key list`  — show cached + server keys
//!  - `aikey key accept [id]` — download & claim a pending key (re-encrypts locally)
//!  - `aikey key sync`  — refresh metadata from server
//!  - `aikey key use <id>` — activate a key for proxy routing

use secrecy::SecretString;
use std::io::{self, IsTerminal, Write};

use crate::crypto;
use crate::platform_client::{KeyItem, PlatformClient};
use crate::storage::{self, VirtualKeyCacheEntry};

// ---------------------------------------------------------------------------
// account login / status / logout
// ---------------------------------------------------------------------------

/// `aikey account login [--url URL] [--email EMAIL] [--password PASSWORD]`
///
/// Connects to an aikey-control-service and stores the JWT in the local
/// `platform_account` table (no network traffic on subsequent commands).
///
/// Flag precedence (highest → lowest):
///   1. CLI flags (`--url`, `--email`, `--password`)
///   2. Environment variables (`AIKEY_CONTROL_URL`, `AIKEY_EMAIL`, `AIKEY_PLATFORM_PASSWORD`)
///   3. Interactive prompts (suppressed in `--json` mode)
pub fn handle_login(
    json_mode: bool,
    flag_url: Option<String>,
    flag_email: Option<String>,
    flag_password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_url = std::env::var("AIKEY_CONTROL_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());

    let control_url = if let Some(u) = flag_url {
        u
    } else if json_mode {
        std::env::var("AIKEY_CONTROL_URL")
            .map_err(|_| "AIKEY_CONTROL_URL env var required in non-interactive mode (or use --url)")?
    } else {
        print!("Control service URL [{}]: ", default_url);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() { default_url } else { trimmed }
    };

    let email = if let Some(e) = flag_email {
        e
    } else if json_mode {
        std::env::var("AIKEY_EMAIL")
            .map_err(|_| "AIKEY_EMAIL env var required in non-interactive mode (or use --email)")?
    } else {
        print!("Email: ");
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        buf.trim().to_string()
    };

    if email.is_empty() {
        return Err("Email cannot be empty".into());
    }

    let password = if let Some(p) = flag_password {
        p
    } else if json_mode {
        std::env::var("AIKEY_PLATFORM_PASSWORD")
            .map_err(|_| "AIKEY_PLATFORM_PASSWORD env var required in non-interactive mode (or use --password)")?
    } else {
        rpassword::prompt_password("Password: ")
            .map_err(|e| format!("Failed to read password: {}", e))?
    };

    if !json_mode {
        println!("Connecting to {}…", control_url);
    }

    let resp = PlatformClient::login(&control_url, &email, &password)
        .map_err(|e| format!("Login failed: {}", e))?;

    storage::save_platform_account(
        &resp.account.account_id,
        &resp.account.email,
        &resp.token,
        &control_url,
    )?;

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "account_id": resp.account.account_id,
            "email": resp.account.email,
        }));
    } else {
        println!("Logged in as {} ({})", resp.account.email, resp.account.account_id);
        println!("Run 'aikey key list' to view your team keys.");
    }
    Ok(())
}

/// `aikey account status`
pub fn handle_account_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    match storage::get_platform_account()? {
        Some(acc) => {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "logged_in": true,
                    "account_id": acc.account_id,
                    "email": acc.email,
                    "control_url": acc.control_url,
                }));
            } else {
                println!("Logged in as : {} ({})", acc.email, acc.account_id);
                println!("Control URL  : {}", acc.control_url);
            }
        }
        None => {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "logged_in": false,
                }));
            } else {
                println!("Not logged in.");
                println!("Run 'aikey account login' to connect to a control service.");
            }
        }
    }
    Ok(())
}

/// `aikey account logout`
pub fn handle_logout(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    storage::clear_platform_account()?;
    if json_mode {
        crate::json_output::print_json(serde_json::json!({ "ok": true }));
    } else {
        println!("Logged out.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key list
// ---------------------------------------------------------------------------

/// `aikey key list`
///
/// Fetches all team keys from the control service (if logged in) and merges
/// with local cache, then displays a table.  No vault password required —
/// key material stays encrypted; only metadata is shown.
pub fn handle_key_list(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Try to refresh from server.
    let server_items: Option<Vec<KeyItem>> = match storage::get_platform_account()? {
        Some(acc) => {
            let client = PlatformClient::new(&acc.control_url, &acc.jwt_token);
            match client.get_all_keys() {
                Ok(items) => {
                    // Sync metadata into local cache (no re-encryption; provider_key stays as-is).
                    for item in &items {
                        let existing = storage::get_virtual_key_cache(&item.virtual_key_id)?;
                        let local_state = existing
                            .as_ref()
                            .map(|e| e.local_state.clone())
                            .unwrap_or_else(|| "synced_inactive".to_string());
                        let nonce = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
                        let ciphertext = existing
                            .as_ref()
                            .and_then(|e| e.provider_key_ciphertext.clone());

                        // Preserve fields that are only populated during `key accept`
                        // (base_url, credential_id, credential_revision, virtual_key_revision).
                        // Overwriting them with empty strings here would erase the data
                        // downloaded at accept time, breaking proxy routing.
                        let base_url = existing.as_ref().map(|e| e.base_url.clone()).unwrap_or_default();
                        let credential_id = existing.as_ref().map(|e| e.credential_id.clone()).unwrap_or_default();
                        let credential_revision = existing.as_ref().map(|e| e.credential_revision.clone()).unwrap_or_default();
                        let virtual_key_revision = existing.as_ref().map(|e| e.virtual_key_revision.clone()).unwrap_or_default();
                        let entry = VirtualKeyCacheEntry {
                            virtual_key_id: item.virtual_key_id.clone(),
                            org_id: item.org_id.clone(),
                            seat_id: item.seat_id.clone(),
                            alias: item.alias.clone(),
                            provider_code: item.provider_code.clone(),
                            protocol_type: "openai_compatible".to_string(),
                            base_url,
                            credential_id,
                            credential_revision,
                            virtual_key_revision,
                            key_status: item.key_status.clone(),
                            share_status: item.share_status.clone(),
                            local_state,
                            expires_at: None,
                            provider_key_nonce: nonce,
                            provider_key_ciphertext: ciphertext,
                            synced_at: 0, // set by upsert
                        };
                        let _ = storage::upsert_virtual_key_cache(&entry);
                    }
                    Some(items)
                }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not reach control service ({}). Showing local cache.", e);
                    }
                    None
                }
            }
        }
        None => None,
    };

    // Read (now-refreshed) local cache.
    let cached = storage::list_virtual_key_cache()?;

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "keys": cached.iter().map(|e| serde_json::json!({
                "virtual_key_id": e.virtual_key_id,
                "alias": e.alias,
                "provider_code": e.provider_code,
                "key_status": e.key_status,
                "share_status": e.share_status,
                "local_state": e.local_state,
                "has_key": e.provider_key_ciphertext.is_some(),
            })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    if cached.is_empty() {
        if server_items.is_none() {
            println!("Not logged in. Run 'aikey account login' to connect.");
        } else {
            println!("No team keys assigned yet.");
        }
        return Ok(());
    }

    // Table header.
    println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<14}  {}",
        "ID", "ALIAS", "PROVIDER", "STATUS", "SHARE", "LOCAL");
    println!("{}", "─".repeat(110));

    for e in &cached {
        let has_key = if e.provider_key_ciphertext.is_some() { "✓" } else { "" };
        let share = match e.share_status.as_str() {
            "pending_claim" => "pending  ←",
            other => other,
        };
        println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<14}  {:<14}  {}",
            &e.virtual_key_id,
            truncate(&e.alias, 20),
            &e.provider_code,
            &e.key_status,
            share,
            &e.local_state,
            has_key,
        );
    }

    let pending_count = cached.iter().filter(|e| e.share_status == "pending_claim").count();
    if pending_count > 0 {
        println!();
        println!("  {} key(s) pending. Run 'aikey key accept' to download all.", pending_count);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key accept
// ---------------------------------------------------------------------------

/// `aikey key accept [id]`
///
/// With no argument: fetches all pending keys from the server and accepts every
/// one in a single pass (vault password prompted once).
/// With an explicit id: accepts only that specific key (original behaviour).
///
/// Downloads the real provider key for each target, re-encrypts it with the
/// local vault AES key, stores in `managed_virtual_keys_cache`, and marks each
/// key as claimed on the server.
pub fn handle_key_accept(
    id: Option<&str>,
    password: &SecretString,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let acc = storage::get_platform_account()?
        .ok_or("Not logged in. Run 'aikey account login' first.")?;

    let client = PlatformClient::new(&acc.control_url, &acc.jwt_token);

    // Build the list of key IDs to accept.
    let ids_to_accept: Vec<String> = match id {
        Some(given_id) => vec![given_id.to_string()],
        None => {
            // No id given → accept all pending keys.
            let pending = client.get_pending_keys()?;
            if pending.is_empty() {
                if json_mode {
                    crate::json_output::print_json(serde_json::json!({
                        "ok": true,
                        "accepted": 0,
                        "message": "No pending keys."
                    }));
                } else {
                    println!("No pending team keys.");
                }
                return Ok(());
            }
            pending.into_iter().map(|k| k.virtual_key_id).collect()
        }
    };

    // Derive vault AES key once for all keys in this batch.
    let vault_key = derive_vault_key(password)?;

    let mut accepted: Vec<serde_json::Value> = Vec::new();

    for virtual_key_id in &ids_to_accept {
        if !json_mode {
            println!("Fetching key {}…", virtual_key_id);
        }

        // Fetch full delivery payload (includes plaintext provider key over TLS).
        let payload = match client.get_key_delivery(virtual_key_id) {
            Ok(p) => p,
            Err(e) => {
                if json_mode {
                    accepted.push(serde_json::json!({
                        "ok": false,
                        "virtual_key_id": virtual_key_id,
                        "error": e.to_string(),
                    }));
                } else {
                    eprintln!("Warning: could not fetch key {}: {}", virtual_key_id, e);
                }
                continue;
            }
        };

        let (nonce, ciphertext) = crypto::encrypt(&vault_key, payload.provider_key.as_bytes())
            .map_err(|e| format!("Failed to encrypt provider key: {}", e))?;

        let entry = VirtualKeyCacheEntry {
            virtual_key_id: payload.virtual_key_id.clone(),
            org_id: payload.org_id.clone(),
            seat_id: payload.seat_id.clone(),
            alias: payload.alias.clone(),
            provider_code: payload.provider_code.clone(),
            protocol_type: payload.protocol_type.clone(),
            base_url: payload.base_url.clone(),
            credential_id: payload.credential_id.clone(),
            credential_revision: payload.credential_revision.clone(),
            virtual_key_revision: payload.current_revision.clone(),
            key_status: payload.key_status.clone(),
            share_status: "claimed".to_string(),
            local_state: "synced_inactive".to_string(),
            expires_at: None,
            provider_key_nonce: Some(nonce),
            provider_key_ciphertext: Some(ciphertext),
            synced_at: 0,
        };
        storage::upsert_virtual_key_cache(&entry)?;

        // Tell the server it is claimed.
        client.claim_key(virtual_key_id)?;

        if json_mode {
            accepted.push(serde_json::json!({
                "ok": true,
                "virtual_key_id": virtual_key_id,
                "alias": payload.alias,
                "provider_code": payload.provider_code,
            }));
        } else {
            println!("Key '{}' ({}) accepted and stored locally.", payload.alias, payload.provider_code);
            println!("Run 'aikey key use {}' to make it active for proxy routing.", virtual_key_id);
        }
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "accepted": accepted.len(),
            "keys": accepted,
        }));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key sync
// ---------------------------------------------------------------------------

/// `aikey key sync`
///
/// Refreshes all key metadata from the control service.  For keys that have
/// already been delivered (`share_status = claimed`) but are missing their
/// local ciphertext, re-fetches the delivery payload and re-encrypts.
pub fn handle_key_sync(
    password: &SecretString,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let acc = storage::get_platform_account()?
        .ok_or("Not logged in. Run 'aikey account login' first.")?;

    let client = PlatformClient::new(&acc.control_url, &acc.jwt_token);

    // Fetch all key metadata.
    let items = client.get_all_keys()?;
    let mut synced = 0usize;
    let mut downloaded = 0usize;

    let vault_key = derive_vault_key(password)?;

    for item in &items {
        let existing = storage::get_virtual_key_cache(&item.virtual_key_id)?;

        // Check if we need to (re-)download the actual key material.
        let needs_download = item.share_status == "claimed"
            && existing
                .as_ref()
                .map(|e| e.provider_key_ciphertext.is_none())
                .unwrap_or(true);

        if needs_download {
            match client.get_key_delivery(&item.virtual_key_id) {
                Ok(payload) => {
                    let (nonce, ciphertext) =
                        crypto::encrypt(&vault_key, payload.provider_key.as_bytes())
                            .map_err(|e| format!("Failed to encrypt provider key: {}", e))?;

                    let local_state = existing
                        .as_ref()
                        .map(|e| e.local_state.clone())
                        .unwrap_or_else(|| "synced_inactive".to_string());

                    let entry = VirtualKeyCacheEntry {
                        virtual_key_id: payload.virtual_key_id.clone(),
                        org_id: payload.org_id.clone(),
                        seat_id: payload.seat_id.clone(),
                        alias: payload.alias.clone(),
                        provider_code: payload.provider_code.clone(),
                        protocol_type: payload.protocol_type.clone(),
                        base_url: payload.base_url.clone(),
                        credential_id: payload.credential_id.clone(),
                        credential_revision: payload.credential_revision.clone(),
                        virtual_key_revision: payload.current_revision.clone(),
                        key_status: payload.key_status.clone(),
                        share_status: payload.share_status.clone(),
                        local_state,
                        expires_at: None,
                        provider_key_nonce: Some(nonce),
                        provider_key_ciphertext: Some(ciphertext),
                        synced_at: 0,
                    };
                    storage::upsert_virtual_key_cache(&entry)?;
                    downloaded += 1;
                }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not fetch delivery for {}: {}", item.virtual_key_id, e);
                    }
                }
            }
        } else {
            // Metadata-only update.
            let local_state = existing
                .as_ref()
                .map(|e| e.local_state.clone())
                .unwrap_or_else(|| "synced_inactive".to_string());
            let nonce = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
            let ciphertext = existing.as_ref().and_then(|e| e.provider_key_ciphertext.clone());
            let base_url = existing.as_ref().map(|e| e.base_url.clone()).unwrap_or_default();
            let credential_id = existing.as_ref().map(|e| e.credential_id.clone()).unwrap_or_default();
            let credential_revision = existing.as_ref().map(|e| e.credential_revision.clone()).unwrap_or_default();
            let virtual_key_revision = existing.as_ref().map(|e| e.virtual_key_revision.clone()).unwrap_or_default();

            let entry = VirtualKeyCacheEntry {
                virtual_key_id: item.virtual_key_id.clone(),
                org_id: item.org_id.clone(),
                seat_id: item.seat_id.clone(),
                alias: item.alias.clone(),
                provider_code: item.provider_code.clone(),
                protocol_type: "openai_compatible".to_string(),
                base_url,
                credential_id,
                credential_revision,
                virtual_key_revision,
                key_status: item.key_status.clone(),
                share_status: item.share_status.clone(),
                local_state,
                expires_at: None,
                provider_key_nonce: nonce,
                provider_key_ciphertext: ciphertext,
                synced_at: 0,
            };
            storage::upsert_virtual_key_cache(&entry)?;
        }
        synced += 1;
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "synced": synced,
            "downloaded": downloaded,
        }));
    } else {
        println!("Sync complete: {} key(s) updated, {} key(s) downloaded.", synced, downloaded);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key use
// ---------------------------------------------------------------------------

/// `aikey key use <id>`
///
/// Marks a virtual key as `active` in the local cache so the proxy will use
/// it for requests targeting that provider.  No vault password required.
pub fn handle_key_use(virtual_key_id: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let entry = storage::get_virtual_key_cache(virtual_key_id)?
        .ok_or_else(|| format!("Virtual key '{}' not found in local cache. Run 'aikey key sync' first.", virtual_key_id))?;

    if entry.provider_key_ciphertext.is_none() {
        return Err(format!(
            "Key '{}' has not been delivered yet. Run 'aikey key accept {}' first.",
            entry.alias, virtual_key_id
        ).into());
    }

    storage::set_virtual_key_local_state(virtual_key_id, "active")?;

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "virtual_key_id": virtual_key_id,
            "local_state": "active",
        }));
    } else {
        println!("Key '{}' ({}) is now active.", entry.alias, entry.provider_code);
        println!("Restart aikey-proxy to apply the change: aikey proxy restart");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Startup interactive accept prompt
// ---------------------------------------------------------------------------

/// Called at the start of any non-Key, non-Account command (interactive mode only).
///
/// If the local cache contains pending team keys **and** the user is logged in,
/// prompts: "Accept now? [y/N]".  On confirmation, reads the vault password once
/// and accepts every pending key automatically.  All failures are silently swallowed
/// so that the original command always proceeds uninterrupted.
pub fn maybe_prompt_accept_pending() -> Result<(), String> {
    // Fast path: nothing pending in local cache (no DB, no network).
    let count = storage::count_pending_virtual_keys().unwrap_or(0);
    if count == 0 {
        return Ok(());
    }

    // Must be logged in — if not, skip silently.
    if storage::get_platform_account().ok().flatten().is_none() {
        return Ok(());
    }

    // Only prompt when stderr is an interactive TTY.
    if !io::stderr().is_terminal() {
        return Ok(());
    }

    eprint!(
        "\nYou have {} pending team key(s). Accept now? [y/N] ",
        count
    );
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return Ok(());
    }
    if input.trim().to_lowercase() != "y" {
        eprintln!(); // blank line before the original command output
        return Ok(());
    }

    // Collect pending IDs from local cache (avoid a network round-trip just for IDs).
    let pending_ids: Vec<String> = storage::list_virtual_key_cache()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.share_status == "pending_claim")
        .map(|e| e.virtual_key_id)
        .collect();

    if pending_ids.is_empty() {
        return Ok(());
    }

    // Prompt for vault password once for all keys.
    let password_str = match rpassword::prompt_password("Vault master password: ") {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    let password = SecretString::new(password_str);

    eprintln!();
    for id in &pending_ids {
        match handle_key_accept(Some(id.as_str()), &password, false) {
            Ok(_) => {}
            Err(e) => eprintln!("Warning: could not accept key {}: {}", id, e),
        }
    }
    eprintln!(); // blank line before the original command output

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derives the vault AES key from the master password.
/// Uses the same salt + KDF parameters stored in the vault DB.
fn derive_vault_key(
    password: &SecretString,
) -> Result<[u8; crypto::KEY_SIZE], String> {
    let salt = storage::get_salt()?;
    let (m, t, p) = storage::get_kdf_params()?;
    let secure_key = crypto::derive_key_with_params(password, &salt, m, t, p)?;
    Ok(*secure_key)
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

//! Basic AiKey SDK usage example.
//!
//! Run with:
//!   AIKEY_PASSWORD=<your-master-password> cargo run --example basic -- [alias] [provider]
//!
//! Arguments (both optional):
//!   alias    — vault alias to fetch directly (default: "my-openai-key")
//!   provider — provider name to resolve     (default: "openai")

use aikey_sdk::AikeyClient;
use secrecy::SecretString;
use std::env;

fn main() {
    let password = env::var("AIKEY_PASSWORD")
        .expect("Set AIKEY_PASSWORD env var to your master password");

    let args: Vec<String> = env::args().collect();
    let alias    = args.get(1).map(String::as_str).unwrap_or("my-openai-key");
    let provider = args.get(2).map(String::as_str).unwrap_or("openai");

    let client = AikeyClient::new(SecretString::new(password.into()));

    // 1. Static env-var lookup — no vault, no password needed
    println!(
        "[1] env var for '{}' → {}",
        provider,
        AikeyClient::env_var_for(provider)
    );

    // 2. Fetch a secret directly by alias
    match client.get_secret(alias) {
        Ok(secret) => println!("[2] get_secret('{}') → <{} chars>", alias, secret.len()),
        Err(e)     => eprintln!("[2] get_secret('{}') failed: {}", alias, e),
    }

    // 3. Resolve a provider → env-var name + secret (reads aikey.config.json if present)
    match client.resolve_provider(provider, None) {
        Ok(ps) => {
            println!(
                "[3] resolve_provider('{}') → alias='{}', env_var='{}', model={:?}, secret=<{} chars>",
                provider, ps.key_alias, ps.env_var, ps.model, ps.secret.len()
            );
        }
        Err(e) => eprintln!("[3] resolve_provider('{}') failed: {}", provider, e),
    }
}

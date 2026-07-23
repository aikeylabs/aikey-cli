//! Crate-wide mutex serialising env-var mutations across unit tests.
//!
//! Why one shared lock instead of per-module locks:
//! `cargo test` runs tests across modules in parallel. HOME / SHELL /
//! USERPROFILE / AIKEY_SHELL_OVERRIDE are process-global, so two tests
//! that mutate them race even when each holds its own private mutex.
//! A `shell_integration::hook_tests` test that set HOME=tmp would still
//! see `path_helper_tests::resolve_user_home_falls_back_to_userprofile_when_home_unset`
//! call `remove_var("HOME")` mid-flight — `resolve_user_home()` then fell
//! back to `dirs::home_dir()` (the real `/Users/<user>`), the real `~/.zshrc`
//! had no v3 marker, and the v3-marker assertion at
//! `shell_integration.rs:2864` flaked. Same hazard exists between
//! `session.rs::tests` and any shell_integration test on HOME.
//!
//! Centralising on one process-level mutex eliminates the cross-module
//! race. Any future unit test in this crate that mutates a process-global
//! env var must lock `ENV_MUTATION_LOCK` for its duration.

#![cfg(test)]

pub static ENV_MUTATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Isolates tests that need both a temporary user home and a temporary vault.
///
/// The lock order is deliberately ENV_MUTATION_LOCK then TEST_VAULT_LOCK. It
/// matches the established cross-module order and prevents deadlocks. Keeping
/// both variables behind one guard also prevents a test that reads
/// `~/.aikey/active-cluster.json` from accidentally inheriting the developer's
/// live cluster state while its database points at a temporary vault.
pub struct HomeVaultEnvGuard {
    _env_guard: std::sync::MutexGuard<'static, ()>,
    _vault_guard: std::sync::MutexGuard<'static, ()>,
    previous_home: Option<std::ffi::OsString>,
    previous_vault_path: Option<std::ffi::OsString>,
}

impl HomeVaultEnvGuard {
    pub fn new(home: &std::path::Path, vault_path: &std::path::Path) -> Self {
        let env_guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vault_guard = crate::storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous_home = std::env::var_os("HOME");
        let previous_vault_path = std::env::var_os("AK_VAULT_PATH");
        unsafe {
            std::env::set_var("HOME", home);
            std::env::set_var("AK_VAULT_PATH", vault_path);
        }
        Self {
            _env_guard: env_guard,
            _vault_guard: vault_guard,
            previous_home,
            previous_vault_path,
        }
    }
}

impl Drop for HomeVaultEnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match &self.previous_vault_path {
                Some(value) => std::env::set_var("AK_VAULT_PATH", value),
                None => std::env::remove_var("AK_VAULT_PATH"),
            }
        }
    }
}

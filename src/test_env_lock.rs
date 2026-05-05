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

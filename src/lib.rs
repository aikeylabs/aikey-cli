//! AiKeyLabs AK - Secure local-first secret management
//!
//! This library provides the core functionality for the AK CLI tool.

pub mod crypto;
pub mod storage;
pub mod synapse;
pub mod executor;
pub mod audit;
pub mod ratelimit;
pub mod config;
pub mod env_resolver;
pub mod env_renderer;
pub mod commands_project;
pub mod commands_env;
pub mod json_output;
pub mod global_config;
pub mod error_codes;
pub mod profiles;
pub mod core;
pub mod providers;
pub mod resolver;
pub mod events;
pub mod observability;
pub mod platform_client;
pub mod commands_account;
pub mod commands_proxy;
pub mod session;

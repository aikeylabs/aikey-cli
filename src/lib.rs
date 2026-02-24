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
pub mod rpc;
pub mod daemon;
pub mod daemon_client;
pub mod profiles;
pub mod core;

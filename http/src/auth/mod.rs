// Ave HTTP Auth System
//
// Complete authentication and authorization system with:
// - Users, roles, and permissions
// - API key management with expiration
// - Audit logging
// - Rate limiting
// - Account lockout
// - SQLite-based storage

pub mod config;
pub mod crypto;
pub mod database;
mod database_apikeys;
mod database_audit;
mod database_ext;
pub mod middleware;
pub mod models;

// Handler modules
pub mod admin_handlers;
pub mod apikey_handlers;
pub mod integration;
pub mod login_handler;
pub mod system_handlers;

// Re-exports for convenience
pub use config::AuthConfig;
pub use database::AuthDatabase;

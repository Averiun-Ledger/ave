// Ave HTTP Auth System - Database Layer
//
// This module provides the database access layer for the auth system using SQLite

use crate::auth::validate_password;

use super::database_audit::AuditLogParams;
use super::crypto::hash_password;
use super::db_runtime::{AuthDbRuntime, PooledConnection, auth_tuning_for_ram};
use super::models::*;
use super::system_config::SystemConfigKey;
use super::{MAINTENANCE_LIMITS, PASSWORD_POLICY, VALIDATION_LIMITS};
use ave_bridge::{
    MachineSpec,
    auth::{AuthConfig, EndpointRateLimit},
    resolve_spec,
};
use rand::RngExt;
use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult,
    TransactionBehavior, params,
};
use std::{
    fs,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

const TARGET: &str = "ave::http::auth";
const BLOCKING_TASK_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

// =============================================================================
// ERROR TYPE
// =============================================================================

#[derive(Debug, Error, Clone)]
pub enum DatabaseError {
    #[error("failed to initialize: {0}")]
    Initialize(String),

    #[error("database connection failed: {0}")]
    Connection(String),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("query failed: {0}")]
    Query(String),

    #[error("insert failed: {0}")]
    Insert(String),

    #[error("update failed: {0}")]
    Update(String),

    #[error("delete failed: {0}")]
    Delete(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("crypto operation failed: {0}")]
    Crypto(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("account locked: {0}")]
    AccountLocked(String),

    #[error("rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("duplicate entry: {0}")]
    Duplicate(String),

    #[error("password change required: {0}")]
    PasswordChangeRequired(String),
}

// =============================================================================
#[derive(Default)]
struct DbMetrics {
    primary_lock_wait_ns_total: AtomicU64,
    primary_lock_wait_count: AtomicU64,
    primary_lock_wait_ns_max: AtomicU64,
    maintenance_lock_wait_ns_total: AtomicU64,
    maintenance_lock_wait_count: AtomicU64,
    maintenance_lock_wait_ns_max: AtomicU64,
    transaction_duration_ns_total: AtomicU64,
    transaction_count: AtomicU64,
    transaction_duration_ns_max: AtomicU64,
    blocking_queue_wait_ns_total: AtomicU64,
    blocking_queue_wait_count: AtomicU64,
    blocking_queue_wait_ns_max: AtomicU64,
    blocking_rejections_total: AtomicU64,
    blocking_task_duration_ns_total: AtomicU64,
    blocking_task_count: AtomicU64,
    blocking_task_duration_ns_max: AtomicU64,
    request_db_ops_total: AtomicU64,
    request_count: AtomicU64,
    request_db_duration_ns_total: AtomicU64,
    request_db_duration_ns_max: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct DbMetricsSnapshot {
    pub primary_lock_wait_count: u64,
    pub primary_lock_wait_avg_ms: f64,
    pub primary_lock_wait_max_ms: f64,
    pub maintenance_lock_wait_count: u64,
    pub maintenance_lock_wait_avg_ms: f64,
    pub maintenance_lock_wait_max_ms: f64,
    pub transaction_count: u64,
    pub transaction_avg_ms: f64,
    pub transaction_max_ms: f64,
    pub blocking_queue_wait_count: u64,
    pub blocking_queue_wait_avg_ms: f64,
    pub blocking_queue_wait_max_ms: f64,
    pub blocking_rejections_total: u64,
    pub blocking_task_count: u64,
    pub blocking_task_avg_ms: f64,
    pub blocking_task_max_ms: f64,
    pub request_count: u64,
    pub avg_db_ops_per_request: f64,
    pub avg_request_db_ms: f64,
    pub max_request_db_ms: f64,
}

struct RuntimeAuthConfig {
    api_key_default_ttl_seconds: AtomicI64,
    api_key_max_keys_per_user: AtomicU32,
    max_login_attempts: AtomicU32,
    lockout_duration_seconds: AtomicI64,
    rate_limit_enable: AtomicBool,
    rate_limit_window_seconds: AtomicI64,
    rate_limit_max_requests: AtomicU32,
    rate_limit_limit_by_key: AtomicBool,
    rate_limit_limit_by_ip: AtomicBool,
    rate_limit_cleanup_interval_seconds: AtomicI64,
    rate_limit_sensitive_endpoints: RwLock<Vec<EndpointRateLimit>>,
    audit_enable: AtomicBool,
    audit_retention_days: AtomicU32,
    audit_max_entries: AtomicU32,
}

impl RuntimeAuthConfig {
    fn from_config(config: &AuthConfig) -> Self {
        Self {
            api_key_default_ttl_seconds: AtomicI64::new(
                config.api_key.default_ttl_seconds,
            ),
            api_key_max_keys_per_user: AtomicU32::new(
                config.api_key.max_keys_per_user,
            ),
            max_login_attempts: AtomicU32::new(config.lockout.max_attempts),
            lockout_duration_seconds: AtomicI64::new(
                config.lockout.duration_seconds,
            ),
            rate_limit_enable: AtomicBool::new(config.rate_limit.enable),
            rate_limit_window_seconds: AtomicI64::new(
                config.rate_limit.window_seconds,
            ),
            rate_limit_max_requests: AtomicU32::new(
                config.rate_limit.max_requests,
            ),
            rate_limit_limit_by_key: AtomicBool::new(
                config.rate_limit.limit_by_key,
            ),
            rate_limit_limit_by_ip: AtomicBool::new(
                config.rate_limit.limit_by_ip,
            ),
            rate_limit_cleanup_interval_seconds: AtomicI64::new(
                config.rate_limit.cleanup_interval_seconds,
            ),
            rate_limit_sensitive_endpoints: RwLock::new(
                config.rate_limit.sensitive_endpoints.clone(),
            ),
            audit_enable: AtomicBool::new(config.session.audit_enable),
            audit_retention_days: AtomicU32::new(
                config.session.audit_retention_days,
            ),
            audit_max_entries: AtomicU32::new(config.session.audit_max_entries),
        }
    }
}

// Dummy password hash for timing attack mitigation
// This is a real Argon2id hash generated with the same parameters as user passwords
// to ensure identical verification cost whether user exists or not
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$6bLVReaW/buHRwX6rLPCJA$KNXZtbxs0tqTOOuCkWFPldX2ri4wFgAVVFJqixUK/Kw";

/// Thread-safe database service for auth operations
#[derive(Clone)]
pub struct AuthDatabase {
    runtime: Arc<AuthDbRuntime>,
    metrics: Arc<DbMetrics>,
    blocking_task_semaphore: Arc<Semaphore>,
    #[cfg(feature = "prometheus")]
    prometheus: Arc<std::sync::OnceLock<super::metrics::SharedAuthPrometheusMetrics>>,
    runtime_config: Arc<RuntimeAuthConfig>,
    pub(crate) config: Arc<AuthConfig>,
}

impl AuthDatabase {
    fn duration_to_ns(duration: Duration) -> u64 {
        duration.as_nanos().min(u64::MAX as u128) as u64
    }

    fn ns_to_ms(ns: u64) -> f64 {
        ns as f64 / 1_000_000.0
    }

    fn duration_to_seconds(duration: Duration) -> f64 {
        duration.as_secs_f64()
    }

    fn avg_ns_to_ms(total: u64, count: u64) -> f64 {
        if count == 0 {
            0.0
        } else {
            Self::ns_to_ms(total / count)
        }
    }

    fn update_max(target: &AtomicU64, value: u64) {
        let mut current = target.load(Ordering::Relaxed);
        while value > current {
            match target.compare_exchange(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn record_lock_wait(&self, pool_name: &'static str, elapsed: Duration) {
        let ns = Self::duration_to_ns(elapsed);
        let elapsed_ms = Self::ns_to_ms(ns);

        match pool_name {
            "primary" => {
                self.metrics
                    .primary_lock_wait_ns_total
                    .fetch_add(ns, Ordering::Relaxed);
                self.metrics
                    .primary_lock_wait_count
                    .fetch_add(1, Ordering::Relaxed);
                Self::update_max(&self.metrics.primary_lock_wait_ns_max, ns);
            }
            "maintenance" => {
                self.metrics
                    .maintenance_lock_wait_ns_total
                    .fetch_add(ns, Ordering::Relaxed);
                self.metrics
                    .maintenance_lock_wait_count
                    .fetch_add(1, Ordering::Relaxed);
                Self::update_max(
                    &self.metrics.maintenance_lock_wait_ns_max,
                    ns,
                );
            }
            _ => {}
        }

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            let elapsed_seconds = Self::duration_to_seconds(elapsed);
            match pool_name {
                "primary" | "maintenance" => {
                    metrics.observe_lock_wait(pool_name, elapsed_seconds)
                }
                _ => {}
            }
        }

        if elapsed >= Duration::from_millis(10) {
            warn!(
                target: TARGET,
                pool = pool_name,
                elapsed_ms,
                "slow auth db pool wait"
            );
        }
    }

    pub(crate) fn record_transaction_duration(
        &self,
        operation: &'static str,
        elapsed: Duration,
    ) {
        let ns = Self::duration_to_ns(elapsed);
        let elapsed_ms = Self::ns_to_ms(ns);

        self.metrics
            .transaction_duration_ns_total
            .fetch_add(ns, Ordering::Relaxed);
        self.metrics
            .transaction_count
            .fetch_add(1, Ordering::Relaxed);
        Self::update_max(&self.metrics.transaction_duration_ns_max, ns);

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            metrics.observe_transaction_duration(
                operation,
                Self::duration_to_seconds(elapsed),
            );
        }

        if elapsed >= Duration::from_millis(25) {
            warn!(
                target: TARGET,
                operation,
                elapsed_ms,
                "slow auth db transaction"
            );
        }
    }

    fn record_blocking_queue_wait(
        &self,
        operation: &'static str,
        elapsed: Duration,
    ) {
        let ns = Self::duration_to_ns(elapsed);
        let elapsed_ms = Self::ns_to_ms(ns);

        self.metrics
            .blocking_queue_wait_ns_total
            .fetch_add(ns, Ordering::Relaxed);
        self.metrics
            .blocking_queue_wait_count
            .fetch_add(1, Ordering::Relaxed);
        Self::update_max(&self.metrics.blocking_queue_wait_ns_max, ns);

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            metrics.observe_blocking_queue_wait(
                operation,
                Self::duration_to_seconds(elapsed),
            );
        }

        if elapsed >= Duration::from_millis(10) {
            warn!(
                target: TARGET,
                operation,
                elapsed_ms,
                "slow auth db blocking queue wait"
            );
        }
    }

    fn record_blocking_rejection(&self, operation: &'static str) {
        self.metrics
            .blocking_rejections_total
            .fetch_add(1, Ordering::Relaxed);

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            metrics.inc_blocking_task_rejection(operation);
        }

        warn!(
            target: TARGET,
            operation,
            timeout_ms = BLOCKING_TASK_QUEUE_TIMEOUT.as_millis(),
            "auth db blocking task rejected due to backpressure"
        );
    }

    fn record_blocking_task_duration(
        &self,
        operation: &'static str,
        elapsed: Duration,
    ) {
        let ns = Self::duration_to_ns(elapsed);
        let elapsed_ms = Self::ns_to_ms(ns);

        self.metrics
            .blocking_task_duration_ns_total
            .fetch_add(ns, Ordering::Relaxed);
        self.metrics
            .blocking_task_count
            .fetch_add(1, Ordering::Relaxed);
        Self::update_max(&self.metrics.blocking_task_duration_ns_max, ns);

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            metrics.observe_blocking_task_duration(
                operation,
                Self::duration_to_seconds(elapsed),
            );
        }

        if elapsed >= Duration::from_millis(50) {
            warn!(
                target: TARGET,
                operation,
                elapsed_ms,
                "slow auth db blocking task"
            );
        }
    }

    pub(crate) fn record_request_db_metrics(
        &self,
        request_kind: &'static str,
        db_operations: u64,
        elapsed: Duration,
    ) {
        let ns = Self::duration_to_ns(elapsed);
        let elapsed_ms = Self::ns_to_ms(ns);

        self.metrics
            .request_db_ops_total
            .fetch_add(db_operations, Ordering::Relaxed);
        self.metrics.request_count.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .request_db_duration_ns_total
            .fetch_add(ns, Ordering::Relaxed);
        Self::update_max(&self.metrics.request_db_duration_ns_max, ns);

        #[cfg(feature = "prometheus")]
        if let Some(metrics) = self.prometheus_metrics() {
            metrics.observe_request_metrics(
                request_kind,
                db_operations,
                Self::duration_to_seconds(elapsed),
            );
        }

        debug!(
            target: TARGET,
            request_kind,
            db_operations,
            elapsed_ms,
            "auth db request metrics"
        );

        if elapsed >= Duration::from_millis(50) {
            warn!(
                target: TARGET,
                request_kind,
                db_operations,
                elapsed_ms,
                "slow auth db request"
            );
        }
    }

    pub fn metrics_snapshot(&self) -> DbMetricsSnapshot {
        let primary_lock_wait_count =
            self.metrics.primary_lock_wait_count.load(Ordering::Relaxed);
        let primary_lock_wait_ns_total =
            self.metrics.primary_lock_wait_ns_total.load(Ordering::Relaxed);
        let primary_lock_wait_ns_max =
            self.metrics.primary_lock_wait_ns_max.load(Ordering::Relaxed);

        let maintenance_lock_wait_count =
            self.metrics.maintenance_lock_wait_count.load(Ordering::Relaxed);
        let maintenance_lock_wait_ns_total = self
            .metrics
            .maintenance_lock_wait_ns_total
            .load(Ordering::Relaxed);
        let maintenance_lock_wait_ns_max = self
            .metrics
            .maintenance_lock_wait_ns_max
            .load(Ordering::Relaxed);

        let transaction_count =
            self.metrics.transaction_count.load(Ordering::Relaxed);
        let transaction_duration_ns_total = self
            .metrics
            .transaction_duration_ns_total
            .load(Ordering::Relaxed);
        let transaction_duration_ns_max = self
            .metrics
            .transaction_duration_ns_max
            .load(Ordering::Relaxed);

        let blocking_queue_wait_count = self
            .metrics
            .blocking_queue_wait_count
            .load(Ordering::Relaxed);
        let blocking_queue_wait_ns_total = self
            .metrics
            .blocking_queue_wait_ns_total
            .load(Ordering::Relaxed);
        let blocking_queue_wait_ns_max = self
            .metrics
            .blocking_queue_wait_ns_max
            .load(Ordering::Relaxed);
        let blocking_rejections_total = self
            .metrics
            .blocking_rejections_total
            .load(Ordering::Relaxed);

        let blocking_task_count =
            self.metrics.blocking_task_count.load(Ordering::Relaxed);
        let blocking_task_duration_ns_total = self
            .metrics
            .blocking_task_duration_ns_total
            .load(Ordering::Relaxed);
        let blocking_task_duration_ns_max = self
            .metrics
            .blocking_task_duration_ns_max
            .load(Ordering::Relaxed);

        let request_count = self.metrics.request_count.load(Ordering::Relaxed);
        let request_db_ops_total =
            self.metrics.request_db_ops_total.load(Ordering::Relaxed);
        let request_db_duration_ns_total = self
            .metrics
            .request_db_duration_ns_total
            .load(Ordering::Relaxed);
        let request_db_duration_ns_max = self
            .metrics
            .request_db_duration_ns_max
            .load(Ordering::Relaxed);

        DbMetricsSnapshot {
            primary_lock_wait_count,
            primary_lock_wait_avg_ms: Self::avg_ns_to_ms(
                primary_lock_wait_ns_total,
                primary_lock_wait_count,
            ),
            primary_lock_wait_max_ms: Self::ns_to_ms(primary_lock_wait_ns_max),
            maintenance_lock_wait_count,
            maintenance_lock_wait_avg_ms: Self::avg_ns_to_ms(
                maintenance_lock_wait_ns_total,
                maintenance_lock_wait_count,
            ),
            maintenance_lock_wait_max_ms: Self::ns_to_ms(
                maintenance_lock_wait_ns_max,
            ),
            transaction_count,
            transaction_avg_ms: Self::avg_ns_to_ms(
                transaction_duration_ns_total,
                transaction_count,
            ),
            transaction_max_ms: Self::ns_to_ms(transaction_duration_ns_max),
            blocking_queue_wait_count,
            blocking_queue_wait_avg_ms: Self::avg_ns_to_ms(
                blocking_queue_wait_ns_total,
                blocking_queue_wait_count,
            ),
            blocking_queue_wait_max_ms: Self::ns_to_ms(
                blocking_queue_wait_ns_max,
            ),
            blocking_rejections_total,
            blocking_task_count,
            blocking_task_avg_ms: Self::avg_ns_to_ms(
                blocking_task_duration_ns_total,
                blocking_task_count,
            ),
            blocking_task_max_ms: Self::ns_to_ms(
                blocking_task_duration_ns_max,
            ),
            request_count,
            avg_db_ops_per_request: if request_count == 0 {
                0.0
            } else {
                request_db_ops_total as f64 / request_count as f64
            },
            avg_request_db_ms: Self::avg_ns_to_ms(
                request_db_duration_ns_total,
                request_count,
            ),
            max_request_db_ms: Self::ns_to_ms(request_db_duration_ns_max),
        }
    }

    #[cfg(feature = "prometheus")]
    pub fn register_prometheus_metrics(
        &self,
        registry: &mut prometheus_client::registry::Registry,
    ) {
        let metrics = self.prometheus.get_or_init(|| {
            let metrics = Arc::new(super::metrics::AuthPrometheusMetrics::new());
            metrics.register_into(registry);
            metrics
        });
        let _ = metrics;
    }

    #[cfg(feature = "prometheus")]
    fn prometheus_metrics(
        &self,
    ) -> Option<&super::metrics::AuthPrometheusMetrics> {
        self.prometheus.get().map(Arc::as_ref)
    }

    pub(crate) fn api_key_default_ttl_seconds(&self) -> i64 {
        self.runtime_config
            .api_key_default_ttl_seconds
            .load(Ordering::Relaxed)
    }

    pub(crate) fn api_key_max_keys_per_user(&self) -> u32 {
        self.runtime_config
            .api_key_max_keys_per_user
            .load(Ordering::Relaxed)
    }

    pub(crate) fn max_login_attempts(&self) -> u32 {
        self.runtime_config
            .max_login_attempts
            .load(Ordering::Relaxed)
    }

    pub(crate) fn lockout_duration_seconds(&self) -> i64 {
        self.runtime_config
            .lockout_duration_seconds
            .load(Ordering::Relaxed)
    }

    pub(crate) fn rate_limit_defaults(&self) -> (u32, i64) {
        (
            self.runtime_config
                .rate_limit_max_requests
                .load(Ordering::Relaxed),
            self.runtime_config
                .rate_limit_window_seconds
                .load(Ordering::Relaxed),
        )
    }

    pub(crate) fn rate_limit_enabled(&self) -> bool {
        self.runtime_config
            .rate_limit_enable
            .load(Ordering::Relaxed)
    }

    pub(crate) fn rate_limit_limit_by_key(&self) -> bool {
        self.runtime_config
            .rate_limit_limit_by_key
            .load(Ordering::Relaxed)
    }

    pub(crate) fn rate_limit_limit_by_ip(&self) -> bool {
        self.runtime_config
            .rate_limit_limit_by_ip
            .load(Ordering::Relaxed)
    }

    pub(crate) fn rate_limit_cleanup_interval_seconds(&self) -> i64 {
        self.runtime_config
            .rate_limit_cleanup_interval_seconds
            .load(Ordering::Relaxed)
    }

    pub(crate) fn rate_limit_sensitive_endpoints(
        &self,
    ) -> Result<Vec<EndpointRateLimit>, DatabaseError> {
        self.runtime_config
            .rate_limit_sensitive_endpoints
            .read()
            .map(|guard| guard.clone())
            .map_err(|e| {
                DatabaseError::Query(format!(
                    "rate limit config lock poisoned: {}",
                    e
                ))
            })
    }

    pub(crate) fn audit_enabled(&self) -> bool {
        self.runtime_config.audit_enable.load(Ordering::Relaxed)
    }

    pub(crate) fn audit_retention_days(&self) -> u32 {
        self.runtime_config
            .audit_retention_days
            .load(Ordering::Relaxed)
    }

    pub(crate) fn audit_max_entries(&self) -> u32 {
        self.runtime_config
            .audit_max_entries
            .load(Ordering::Relaxed)
    }

    pub(crate) fn password_policy(&self) -> &'static super::PasswordPolicy {
        &PASSWORD_POLICY
    }

    pub(crate) fn role_name_max_length(&self) -> usize {
        VALIDATION_LIMITS.role_name_max_length
    }

    pub(crate) fn role_description_max_length(&self) -> usize {
        VALIDATION_LIMITS.role_description_max_length
    }

    pub(crate) fn usage_plan_id_max_length(&self) -> usize {
        VALIDATION_LIMITS.usage_plan_id_max_length
    }

    pub(crate) fn usage_plan_name_max_length(&self) -> usize {
        VALIDATION_LIMITS.usage_plan_name_max_length
    }

    pub(crate) fn users_default_limit(&self) -> i64 {
        VALIDATION_LIMITS.users_default_limit
    }

    pub(crate) fn users_max_limit(&self) -> i64 {
        VALIDATION_LIMITS.users_max_limit
    }

    pub(crate) fn audit_logs_default_limit(&self) -> i64 {
        VALIDATION_LIMITS.audit_logs_default_limit
    }

    pub(crate) fn audit_logs_max_limit(&self) -> i64 {
        VALIDATION_LIMITS.audit_logs_max_limit
    }

    pub(crate) fn audit_cleanup_batch_size(&self) -> i64 {
        MAINTENANCE_LIMITS.audit_cleanup_batch_size
    }

    pub(crate) fn rate_limit_cleanup_batch_size(&self) -> i64 {
        MAINTENANCE_LIMITS.rate_limit_cleanup_batch_size
    }

    pub(crate) fn expired_api_key_cleanup_batch_size(&self) -> i64 {
        MAINTENANCE_LIMITS.expired_api_key_cleanup_batch_size
    }

    pub(crate) fn apply_runtime_system_config_value(
        &self,
        key: SystemConfigKey,
        value: &super::models::SystemConfigValue,
    ) -> Result<(), DatabaseError> {
        match key {
            SystemConfigKey::ApiKeyDefaultTtlSeconds => {
                let super::models::SystemConfigValue::Integer(ttl) = value else {
                    return Err(DatabaseError::Validation(
                        "api_key_default_ttl_seconds expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .api_key_default_ttl_seconds
                    .store(*ttl, Ordering::Relaxed);
            }
            SystemConfigKey::MaxLoginAttempts => {
                let super::models::SystemConfigValue::Integer(attempts) = value else {
                    return Err(DatabaseError::Validation(
                        "max_login_attempts expects an integer".to_string(),
                    ));
                };
                self.runtime_config
                    .max_login_attempts
                    .store(*attempts as u32, Ordering::Relaxed);
            }
            SystemConfigKey::ApiKeyMaxKeysPerUser => {
                let super::models::SystemConfigValue::Integer(max_keys) = value else {
                    return Err(DatabaseError::Validation(
                        "api_key_max_keys_per_user expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .api_key_max_keys_per_user
                    .store(*max_keys as u32, Ordering::Relaxed);
            }
            SystemConfigKey::LockoutDurationSeconds => {
                let super::models::SystemConfigValue::Integer(seconds) = value else {
                    return Err(DatabaseError::Validation(
                        "lockout_duration_seconds expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .lockout_duration_seconds
                    .store(*seconds, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitWindowSeconds => {
                let super::models::SystemConfigValue::Integer(seconds) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_window_seconds expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_window_seconds
                    .store(*seconds, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitEnable => {
                let super::models::SystemConfigValue::Boolean(enabled) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_enable expects a boolean".to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_enable
                    .store(*enabled, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitMaxRequests => {
                let super::models::SystemConfigValue::Integer(max_requests) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_max_requests expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_max_requests
                    .store(*max_requests as u32, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitLimitByKey => {
                let super::models::SystemConfigValue::Boolean(enabled) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_limit_by_key expects a boolean"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_limit_by_key
                    .store(*enabled, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitLimitByIp => {
                let super::models::SystemConfigValue::Boolean(enabled) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_limit_by_ip expects a boolean"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_limit_by_ip
                    .store(*enabled, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitCleanupIntervalSeconds => {
                let super::models::SystemConfigValue::Integer(seconds) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_cleanup_interval_seconds expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .rate_limit_cleanup_interval_seconds
                    .store(*seconds, Ordering::Relaxed);
            }
            SystemConfigKey::RateLimitSensitiveEndpoints => {
                let super::models::SystemConfigValue::EndpointRateLimits(endpoints) = value else {
                    return Err(DatabaseError::Validation(
                        "rate_limit_sensitive_endpoints expects an array"
                            .to_string(),
                    ));
                };
                let mut guard = self
                    .runtime_config
                    .rate_limit_sensitive_endpoints
                    .write()
                    .map_err(|e| {
                        DatabaseError::Query(format!(
                            "rate limit config lock poisoned: {}",
                            e
                        ))
                    })?;
                *guard = endpoints
                    .iter()
                    .cloned()
                    .map(EndpointRateLimit::from)
                    .collect();
            }
            SystemConfigKey::AuditEnable => {
                let super::models::SystemConfigValue::Boolean(enabled) = value else {
                    return Err(DatabaseError::Validation(
                        "audit_enable expects a boolean".to_string(),
                    ));
                };
                self.runtime_config
                    .audit_enable
                    .store(*enabled, Ordering::Relaxed);
            }
            SystemConfigKey::AuditRetentionDays => {
                let super::models::SystemConfigValue::Integer(days) = value else {
                    return Err(DatabaseError::Validation(
                        "audit_retention_days expects an integer"
                            .to_string(),
                    ));
                };
                self.runtime_config
                    .audit_retention_days
                    .store(*days as u32, Ordering::Relaxed);
            }
            SystemConfigKey::AuditMaxEntries => {
                let super::models::SystemConfigValue::Integer(entries) = value else {
                    return Err(DatabaseError::Validation(
                        "audit_max_entries expects an integer".to_string(),
                    ));
                };
                self.runtime_config
                    .audit_max_entries
                    .store(*entries as u32, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Get a locked database connection with error handling
    pub(super) fn lock_conn(
        &self,
    ) -> Result<PooledConnection, DatabaseError> {
        let started = Instant::now();
        let conn = self.runtime.acquire_primary()?;
        self.record_lock_wait("primary", started.elapsed());
        Ok(conn)
    }

    pub(super) fn lock_maintenance_conn(
        &self,
    ) -> Result<PooledConnection, DatabaseError> {
        let started = Instant::now();
        let conn = self.runtime.acquire_maintenance()?;
        self.record_lock_wait("maintenance", started.elapsed());
        Ok(conn)
    }

    pub async fn run_blocking<T, F>(
        &self,
        operation: &'static str,
        work: F,
    ) -> Result<T, DatabaseError>
    where
        T: Send + 'static,
        F: FnOnce(AuthDatabase) -> Result<T, DatabaseError> + Send + 'static,
    {
        let db = self.clone();
        let queue_started = Instant::now();
        let permit = tokio::time::timeout(
            BLOCKING_TASK_QUEUE_TIMEOUT,
            self.blocking_task_semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            self.record_blocking_rejection(operation);
            DatabaseError::Query(format!(
                "auth database is saturated; timed out waiting for capacity for {}",
                operation
            ))
        })?
        .map_err(|_| {
            DatabaseError::Query(
                "auth database backpressure semaphore closed".to_string(),
            )
        })?;
        self.record_blocking_queue_wait(operation, queue_started.elapsed());

        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(db)
        })
            .await
            .map_err(|e| {
                DatabaseError::Query(format!(
                    "blocking db task {} failed: {}",
                    operation, e
                ))
            })?;
        self.record_blocking_task_duration(operation, started.elapsed());
        result
    }

    /// Create a new AuthDatabase instance
    ///
    /// This will:
    /// 1. Create the database file if it doesn't exist
    /// 2. Run migrations to set up the schema
    /// 3. Bootstrap the superadmin account if configured
    pub fn new(
        config: AuthConfig,
        password: &str,
        spec: Option<MachineSpec>,
    ) -> Result<Self, DatabaseError> {
        // Create parent directory if it doesn't exist
        let path = config.database_path.clone();
        if !Path::new(&path).exists() {
            fs::create_dir_all(&path).map_err(|e| {
                DatabaseError::Initialize(format!(
                    "cannot create auth directory: {}",
                    e
                ))
            })?;
        }

        let path = path.join("auth.db");

        // Apply tuning PRAGMAs
        let resolved = resolve_spec(spec.as_ref());
        let tuning = auth_tuning_for_ram(resolved.ram_mb);
        let sync_mode = if config.durability { "FULL" } else { "NORMAL" };
        let pool_size = AuthDbRuntime::recommended_pool_size();
        let runtime = AuthDbRuntime::new(&path, sync_mode, &tuning, pool_size)?;
        let blocking_capacity = pool_size.saturating_mul(2).max(4);

        let db = Self {
            runtime: Arc::new(runtime),
            metrics: Arc::new(DbMetrics::default()),
            blocking_task_semaphore: Arc::new(Semaphore::new(
                blocking_capacity,
            )),
            #[cfg(feature = "prometheus")]
            prometheus: Arc::new(std::sync::OnceLock::new()),
            runtime_config: Arc::new(RuntimeAuthConfig::from_config(&config)),
            config: Arc::new(config),
        };

        // Run migrations
        db.run_migrations()?;

        // Bootstrap superadmin if needed
        db.bootstrap_superadmin(password)?;

        // Seed config keys and load any persisted runtime overrides.
        db.initialize_runtime_system_config()?;

        Ok(db)
    }

    /// Run database migrations
    pub fn run_migrations(&self) -> Result<(), DatabaseError> {
        info!(target: TARGET, "running database migrations");

        let conn = self.lock_conn()?;

        // Read and execute migration files
        let migration_001 =
            include_str!("../../migrations/001_initial_schema.sql");
        conn.execute_batch(migration_001).map_err(|e| {
            DatabaseError::Migration(format!("migration 001 failed: {}", e))
        })?;

        let migration_002 =
            include_str!("../../migrations/002_role_permissions.sql");
        conn.execute_batch(migration_002).map_err(|e| {
            DatabaseError::Migration(format!("migration 002 failed: {}", e))
        })?;

        let migration_003 =
            include_str!("../../migrations/003_usage_plans.sql");
        conn.execute_batch(migration_003).map_err(|e| {
            DatabaseError::Migration(format!("migration 003 failed: {}", e))
        })?;
        drop(conn);

        info!(target: TARGET, "database migrations completed");
        Ok(())
    }

    /// Seed system_config keys from startup config and load persisted overrides.
    fn initialize_runtime_system_config(&self) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;
        let cfg = self.config.clone();

        for key in SystemConfigKey::ALL {
            let startup_value = key.startup_value(&cfg)?;
            let value = key.serialize_value(&startup_value)?;
            conn.execute(
                "INSERT INTO system_config (key, value, description)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                    value = CASE
                        WHEN system_config.updated_by IS NULL THEN excluded.value
                        ELSE system_config.value
                    END,
                    description = COALESCE(system_config.description, excluded.description)",
                params![key.as_str(), value, key.description()],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;

            let persisted_value: String = conn
                .query_row(
                    "SELECT value FROM system_config WHERE key = ?1",
                    params![key.as_str()],
                    |row| row.get(0),
                )
                .map_err(|e| DatabaseError::Query(e.to_string()))?;

            let parsed_value = key.parse_persisted_value(&persisted_value);
            if let Err(err) = parsed_value
                .and_then(|value| self.apply_runtime_system_config_value(key, &value))
            {
                warn!(
                    target: TARGET,
                    key = key.as_str(),
                    value = %persisted_value,
                    error = %err,
                    "invalid persisted auth config override; keeping startup value"
                );
            }
        }
        drop(conn);

        Ok(())
    }

    /// Bootstrap superadmin account on first run
    pub fn bootstrap_superadmin(
        &self,
        password: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if any users exist
        let user_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE is_deleted = 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if user_count > 0 {
            debug!(target: TARGET, "users already exist, skipping superadmin bootstrap");
            return Ok(());
        }

        // Get superadmin config
        let superadmin = if !self.config.superadmin.is_empty() {
            self.config.superadmin.clone()
        } else {
            "admin".to_owned()
        };

        info!(target: TARGET, username = %superadmin, "bootstrapping superadmin account");

        // Hash password
        let password_hash = hash_password(password).map_err(|e| {
            DatabaseError::Crypto(format!(
                "Failed to hash superadmin password: {}",
                e
            ))
        })?;

        // Create superadmin user
        conn.execute(
            "INSERT INTO users (username, password_hash, is_active)
             VALUES (?1, ?2, 1)",
            params![superadmin, password_hash],
        )
        .map_err(|e| {
            DatabaseError::Insert(format!("Failed to create superadmin: {}", e))
        })?;

        let user_id = conn.last_insert_rowid();

        // Assign superadmin role
        let superadmin_role_id: i64 = conn
            .query_row(
                "SELECT id FROM roles WHERE name = 'superadmin'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                DatabaseError::Query(format!(
                    "Failed to get superadmin role: {}",
                    e
                ))
            })?;

        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            params![user_id, superadmin_role_id],
        )
        .map_err(|e| {
            DatabaseError::Insert(format!(
                "Failed to assign superadmin role: {}",
                e
            ))
        })?;
        drop(conn);

        info!(target: TARGET, "superadmin account created");
        Ok(())
    }

    /// Get the current Unix timestamp in seconds
    pub(crate) fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    /// Generate a UUID v4 string (for API key public IDs)
    pub(crate) fn generate_uuid() -> String {
        let mut rng = rand::rng();

        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            0x4000 | (rng.random::<u16>() & 0x0FFF), // Version 4
            0x8000 | (rng.random::<u16>() & 0x3FFF), // Variant 1
            rng.random::<u64>() & 0xFFFF_FFFF_FFFF,
        )
    }

}

// =============================================================================
// USER OPERATIONS
// =============================================================================

impl AuthDatabase {
    fn create_user_with_conn(
        conn: &Connection,
        username: &str,
        password_hash: &str,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
        must_change_password: Option<bool>,
    ) -> Result<User, DatabaseError> {
        Self::validate_username(username)?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 AND is_deleted = 0)",
                params![username],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if exists {
            return Err(DatabaseError::Duplicate(format!(
                "Username '{}' already exists",
                username
            )));
        }
        if let Some(ref roles) = role_ids {
            let superadmin_role_id =
                match Self::get_role_by_name_internal(conn, "superadmin") {
                    Ok(role) => Some(role.id),
                    Err(DatabaseError::NotFound(_)) => None,
                    Err(err) => return Err(err),
                };

            if let Some(sa_role_id) = superadmin_role_id
                && roles.contains(&sa_role_id)
            {
                let existing_count: i64 = conn
                    .query_row(
                        "SELECT COUNT(DISTINCT u.id)
                         FROM users u
                         INNER JOIN user_roles ur ON u.id = ur.user_id
                         INNER JOIN roles r ON ur.role_id = r.id
                         WHERE r.name = 'superadmin' AND u.is_deleted = 0",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| {
                        DatabaseError::Query(format!(
                            "Failed to count superadmins: {}",
                            e
                        ))
                    })?;

                if existing_count > 0 {
                    return Err(DatabaseError::Validation(
                        "A superadmin already exists. Only one superadmin is allowed".to_string(),
                    ));
                }
            }
        }

        let must_change = must_change_password.unwrap_or(true);
        conn.execute(
            "INSERT INTO users (username, password_hash, is_active, must_change_password)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, true, must_change],
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                DatabaseError::Duplicate(format!(
                    "Username '{}' already exists",
                    username
                ))
            } else {
                DatabaseError::Insert(msg)
            }
        })?;

        let user_id = conn.last_insert_rowid();

        if let Some(roles) = role_ids {
            for role_id in roles {
                conn.execute(
                    "INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?1, ?2, ?3)",
                    params![user_id, role_id, created_by],
                ).map_err(|e| DatabaseError::Insert(format!("Failed to assign role: {}", e)))?;
            }
        }

        Self::get_user_by_id_internal(conn, user_id)
    }

    pub fn create_user_transactional(
        &self,
        username: &str,
        password: &str,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
        must_change_password: Option<bool>,
        audit: Option<AuditLogParams>,
    ) -> Result<User, DatabaseError> {
        Self::validate_username(username)?;
        validate_password(password, self.password_policy())
            .map_err(DatabaseError::Validation)?;
        let password_hash = hash_password(password).map_err(|e| {
            DatabaseError::Crypto(format!("Failed to hash password: {}", e))
        })?;

        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;

        let user = Self::create_user_with_conn(
            &tx,
            username,
            &password_hash,
            role_ids,
            created_by,
            must_change_password,
        )?;
        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }
        tx.commit()
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;
        Ok(user)
    }

    /// Internal: Get user by ID without acquiring lock
    pub(crate) fn get_user_by_id_internal(
        conn: &Connection,
        user_id: i64,
    ) -> Result<User, DatabaseError> {
        conn.query_row(
            "SELECT id, username, password_hash, is_active, is_deleted,
                    must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
             FROM users
             WHERE id = ?1 AND is_deleted = 0",
            params![user_id],
            |row| {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_active: row.get(3)?,
                    is_deleted: row.get(4)?,
                    must_change_password: row.get(5)?,
                    failed_login_attempts: row.get(6)?,
                    locked_until: row.get(7)?,
                    last_login_at: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                };
                Ok(user)
            },
        )
        .optional()
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFound(format!("User with id {} not found", user_id)))
    }

    /// Get user by ID
    pub fn get_user_by_id(&self, user_id: i64) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_user_by_id_internal(&conn, user_id)
    }

    /// Count superadmin users (users with the superadmin role)
    pub fn count_superadmins(&self) -> Result<i64, DatabaseError> {
        let count: i64 = self
            .lock_conn()?
            .query_row(
                "SELECT COUNT(DISTINCT u.id)
             FROM users u
             INNER JOIN user_roles ur ON u.id = ur.user_id
             INNER JOIN roles r ON ur.role_id = r.id
             WHERE r.name = 'superadmin' AND u.is_deleted = 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(count)
    }

    /// List all users
    pub fn list_users(
        &self,
        include_inactive: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let query = if include_inactive {
            "SELECT u.id, u.username, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at, u.must_change_password
             FROM users u
             WHERE u.is_deleted = 0
             ORDER BY u.username
             LIMIT ?1 OFFSET ?2"
        } else {
            "SELECT u.id, u.username, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at, u.must_change_password
             FROM users u
             WHERE u.is_deleted = 0 AND u.is_active = 1
             ORDER BY u.username
             LIMIT ?1 OFFSET ?2"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let users = stmt
            .query_map(params![limit, offset], |row| {
                let user_id: i64 = row.get(0)?;
                Ok((
                    user_id,
                    UserInfo {
                        id: user_id,
                        username: row.get(1)?,
                        is_active: row.get(2)?,
                        failed_login_attempts: row.get(3)?,
                        locked_until: row.get(4)?,
                        last_login_at: row.get(5)?,
                        created_at: row.get(6)?,
                        must_change_password: row.get(7)?,
                        roles: Vec::new(), // Will be filled below
                    },
                ))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        drop(stmt);

        // Get roles for each user
        let mut result = Vec::new();
        for (user_id, mut user_info) in users {
            user_info.roles = Self::get_user_roles_internal(&conn, user_id)?;
            result.push(user_info);
        }
        drop(conn);

        Ok(result)
    }

    fn update_user_with_conn(
        &self,
        conn: &Connection,
        user_id: i64,
        password: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<User, DatabaseError> {
        let _ = Self::get_user_by_id_internal(conn, user_id)?;

        if let Some(pwd) = password {
            validate_password(pwd, self.password_policy())
                .map_err(DatabaseError::Validation)?;

            let password_hash = hash_password(pwd).map_err(|e| {
                DatabaseError::Crypto(format!("Failed to hash password: {}", e))
            })?;

            conn.execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 0, failed_login_attempts = 0, locked_until = NULL WHERE id = ?2",
                params![password_hash, user_id],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;

            Self::revoke_user_api_keys_internal(
                conn,
                user_id,
                None,
                "Password changed via update_user",
            )?;
        }

        if let Some(active) = is_active {
            conn.execute(
                "UPDATE users SET is_active = ?1 WHERE id = ?2",
                params![active, user_id],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        }

        Self::get_user_by_id_internal(conn, user_id)
    }

    fn replace_user_roles_with_conn(
        conn: &Connection,
        user_id: i64,
        role_ids: &[i64],
        assigned_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1",
            params![user_id],
        )
        .map_err(|e| DatabaseError::Delete(e.to_string()))?;

        for role_id in role_ids {
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
                 VALUES (?1, ?2, ?3)",
                params![user_id, role_id, assigned_by],
            )
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;
        }

        Self::revoke_user_api_keys_internal(
            conn,
            user_id,
            assigned_by,
            "Role changed",
        )?;

        Ok(())
    }

    pub fn update_user_with_roles_transactional(
        &self,
        user_id: i64,
        password: Option<&str>,
        is_active: Option<bool>,
        role_ids: Option<&[i64]>,
        assigned_by: Option<i64>,
        audit: Option<AuditLogParams>,
    ) -> Result<User, DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        let user = self.update_user_with_conn(&tx, user_id, password, is_active)?;

        if let Some(role_ids) = role_ids {
            Self::replace_user_roles_with_conn(&tx, user_id, role_ids, assigned_by)?;
        }

        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }

        tx.commit()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        Ok(user)
    }

    fn delete_user_with_conn(
        conn: &Connection,
        user_id: i64,
    ) -> Result<(), DatabaseError> {
        conn.execute(
            "UPDATE users SET is_deleted = 1 WHERE id = ?1",
            params![user_id],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        Ok(())
    }

    pub fn delete_user_transactional(
        &self,
        user_id: i64,
        audit: Option<AuditLogParams>,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        Self::delete_user_with_conn(&tx, user_id)?;
        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }
        tx.commit()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        Ok(())
    }

    /// Internal: Get user roles without acquiring lock
    pub(crate) fn get_user_roles_internal(
        conn: &Connection,
        user_id: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let mut stmt = conn
            .prepare(
                "SELECT r.name
             FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?1 AND r.is_deleted = 0
             ORDER BY r.name",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let roles = stmt
            .query_map(params![user_id], |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<String>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(roles)
    }

    /// Get user roles
    pub fn get_user_roles(
        &self,
        user_id: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_user_roles_internal(&conn, user_id)
    }

    pub(crate) fn assign_role_to_user_with_conn(
        conn: &Connection,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
             VALUES (?1, ?2, ?3)",
            params![user_id, role_id, assigned_by],
        )
        .map_err(|e| DatabaseError::Insert(e.to_string()))?;

        Self::revoke_user_api_keys_internal(
            conn,
            user_id,
            assigned_by,
            "Role changed",
        )?;

        Ok(())
    }

    pub fn assign_role_to_user_transactional(
        &self,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
        audit: Option<AuditLogParams>,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;
        Self::assign_role_to_user_with_conn(&tx, user_id, role_id, assigned_by)?;
        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }
        tx.commit()
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;
        Ok(())
    }

    pub(crate) fn remove_role_from_user_with_conn(
        conn: &Connection,
        user_id: i64,
        role_id: i64,
    ) -> Result<(), DatabaseError> {
        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
            params![user_id, role_id],
        )
        .map_err(|e| DatabaseError::Delete(e.to_string()))?;

        Self::revoke_user_api_keys_internal(
            conn,
            user_id,
            None,
            "Role changed",
        )?;
        Ok(())
    }

    pub fn remove_role_from_user_transactional(
        &self,
        user_id: i64,
        role_id: i64,
        audit: Option<AuditLogParams>,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Delete(e.to_string()))?;
        Self::remove_role_from_user_with_conn(&tx, user_id, role_id)?;
        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }
        tx.commit()
            .map_err(|e| DatabaseError::Delete(e.to_string()))?;
        Ok(())
    }

    /// Verify user credentials (username + password)
    ///
    /// SECURITY: This function uses constant-time comparison to prevent username enumeration
    /// via timing attacks. When a user doesn't exist, we still perform a dummy hash computation
    /// to make the response time similar to a failed login for an existing user.
    pub fn verify_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;
        self.verify_credentials_with_conn(&conn, username, password)
    }

    pub(crate) fn verify_credentials_with_conn(
        &self,
        conn: &Connection,
        username: &str,
        password: &str,
    ) -> Result<User, DatabaseError> {

        // Try to find the user
        let user_result = conn.query_row(
            "SELECT id, username, password_hash, is_active, is_deleted,
                    must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
             FROM users
             WHERE username = ?1 AND is_deleted = 0",
            params![username],
            |row| {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_active: row.get(3)?,
                    is_deleted: row.get(4)?,
                    must_change_password: row.get(5)?,
                    failed_login_attempts: row.get(6)?,
                    locked_until: row.get(7)?,
                    last_login_at: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                };
                Ok(user)
            },
        );

        // SECURITY: Constant-time username enumeration mitigation
        // Always perform password hash verification with equal timing
        // Use a real Argon2id hash to ensure identical parameters and computation cost
        let (user, password_valid) = match user_result {
            Ok(u) => {
                // User exists - verify with real hash
                let valid =
                    super::crypto::verify_password(password, &u.password_hash)
                        .map_err(|e| {
                            DatabaseError::Crypto(format!(
                                "Password verification failed: {}",
                                e
                            ))
                        })?;
                (Some(u), valid)
            }
            Err(_) => {
                // User doesn't exist - verify with dummy hash to match timing
                let _ = super::crypto::verify_password(
                    password,
                    DUMMY_PASSWORD_HASH,
                );
                (None, false)
            }
        };

        // If user doesn't exist, return error now (after hash verification for timing)
        let user = user.ok_or_else(|| {
            DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            )
        })?;

        // SECURITY FIX: Use generic error messages to prevent user enumeration
        // Active check
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        // Lockout check
        if let Some(locked_until) = user.locked_until
            && locked_until > Self::now()
        {
            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        // Password was already verified above for timing attack mitigation
        if !password_valid {
            // Increment failed login attempts
            let new_attempts = user.failed_login_attempts + 1;
            let locked_until =
                if new_attempts >= self.max_login_attempts() as i32 {
                    Some(Self::now() + self.lockout_duration_seconds())
                } else {
                    None
                };

            conn.execute(
                "UPDATE users SET failed_login_attempts = ?1, locked_until = ?2 WHERE id = ?3",
                params![new_attempts, locked_until, user.id],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;

            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        // Reset failed login attempts on successful login
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ?1 WHERE id = ?2",
            params![Self::now(), user.id],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        if user.must_change_password {
            return Err(DatabaseError::PasswordChangeRequired(
                "Password change required".to_string(),
            ));
        }

        Ok(user)
    }

    pub fn verify_credentials_transactional(
        &self,
        username: &str,
        password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<User, DatabaseError> {
        if ip_address.is_none() && user_agent.is_none() {
            return self.verify_credentials(username, password);
        }

        let mut conn = self.lock_conn()?;
        let tx_started = std::time::Instant::now();
        let result = (|| {
            let tx = conn
                .transaction()
                .map_err(|e| DatabaseError::Update(e.to_string()))?;

            let user = match self.verify_credentials_with_conn(&tx, username, password) {
                Ok(user) => user,
                Err(err) => {
                    let failed_details =
                        format!("Failed login for username: {}", username);
                    Self::create_audit_log_with_conn(
                        &tx,
                        self.audit_enabled(),
                        crate::auth::database_audit::AuditLogParams {
                            user_id: None,
                            api_key_id: None,
                            action_type: "login_failed",
                            endpoint: Some("/login"),
                            http_method: Some("POST"),
                            ip_address,
                            user_agent,
                            request_id: None,
                            details: Some(&failed_details),
                            success: false,
                            error_message: Some(&err.to_string()),
                        },
                    )?;

                    tx.commit()
                        .map_err(|e| DatabaseError::Update(e.to_string()))?;
                    return Err(err);
                }
            };

            tx.commit()
                .map_err(|e| DatabaseError::Update(e.to_string()))?;

            Ok(user)
        })();
        self.record_transaction_duration(
            "verify_credentials_transactional",
            tx_started.elapsed(),
        );
        result
    }

    /// Calculate all effective permissions for a user
    /// Combines role permissions and user-specific overrides
    pub fn calculate_user_permissions(
        &self,
        user_id: i64,
    ) -> Result<Vec<super::models::Permission>, DatabaseError> {
        // This method is already implemented in database_ext.rs via get_user_effective_permissions
        // We'll use that
        self.get_user_effective_permissions(user_id)
    }

    /// Change password providing current credentials (for forced reset flow)
    ///
    /// SECURITY: This function uses constant-time comparison to prevent username enumeration
    /// via timing attacks. When a user doesn't exist, we still perform a dummy hash computation
    /// to make the response time similar to a failed password change for an existing user.
    pub fn change_password_with_credentials(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;

        let user_result = conn
            .query_row(
                "SELECT id, username, password_hash, is_active, is_deleted,
                        must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
                 FROM users
                 WHERE username = ?1 AND is_deleted = 0",
                params![username],
                |row| {
                    let user = User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        is_active: row.get(3)?,
                        is_deleted: row.get(4)?,
                        must_change_password: row.get(5)?,
                        failed_login_attempts: row.get(6)?,
                        locked_until: row.get(7)?,
                        last_login_at: row.get(8)?,
                        created_at: row.get(9)?,
                        updated_at: row.get(10)?,
                    };
                    Ok(user)
                },
            )
            .optional()
            .map_err(|e| DatabaseError::Query(e.to_string()));

        // SECURITY: Constant-time username enumeration mitigation
        // Always perform password hash verification with equal timing
        // Use a real Argon2id hash to ensure identical parameters and computation cost
        let (user, password_valid) = match user_result {
            Ok(Some(u)) => {
                // User exists - verify with real hash
                let valid = super::crypto::verify_password(
                    current_password,
                    &u.password_hash,
                )
                .map_err(|e| {
                    DatabaseError::Crypto(format!(
                        "Password verification failed: {}",
                        e
                    ))
                })?;
                (Some(u), valid)
            }
            Ok(None) | Err(_) => {
                // User doesn't exist - verify with dummy hash to match timing
                let _ = super::crypto::verify_password(
                    current_password,
                    DUMMY_PASSWORD_HASH,
                );
                (None, false)
            }
        };

        // If user doesn't exist, return error now (after hash verification for timing)
        let mut user = user.ok_or_else(|| {
            DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            )
        })?;

        // Password was already verified above for timing attack mitigation
        if !password_valid {
            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "Account is disabled".to_string(),
            ));
        }
        if let Some(locked_until) = user.locked_until
            && locked_until > Self::now()
        {
            return Err(DatabaseError::AccountLocked(
                "Account is temporarily locked".to_string(),
            ));
        }

        // SECURITY: Only allow password change if it's required
        // This prevents users from resetting their lockout counter by changing password
        if !user.must_change_password {
            return Err(DatabaseError::PermissionDenied(
                "Password change not required. Use authenticated endpoints to change your password".to_string(),
            ));
        }

        // Validate new password
        validate_password(new_password, self.password_policy())
            .map_err(DatabaseError::Validation)?;

        // Prevent setting the same password
        if current_password == new_password {
            return Err(DatabaseError::Validation(
                "New password must be different from current password"
                    .to_string(),
            ));
        }

        let password_hash = hash_password(new_password).map_err(|e| {
            DatabaseError::Crypto(format!("Failed to hash password: {}", e))
        })?;

        conn.execute(
            "UPDATE users
             SET password_hash = ?1, must_change_password = 0, failed_login_attempts = 0, locked_until = NULL, updated_at = strftime('%s','now')
             WHERE id = ?2",
            params![password_hash, user.id],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        // SECURITY FIX: Revoke all API keys when password is changed
        // This prevents compromised accounts from maintaining persistent access
        // via existing API keys after the password has been changed
        Self::revoke_user_api_keys_internal(
            &conn,
            user.id,
            Some(user.id), // User-initiated revocation
            "Password changed by user",
        )?;
        drop(conn);

        // Refresh user
        user.must_change_password = false;
        user.password_hash = password_hash;
        user.failed_login_attempts = 0;
        user.locked_until = None;

        Ok(user)
    }

    fn admin_reset_password_with_conn(
        &self,
        conn: &Connection,
        user_id: i64,
        new_password: &str,
    ) -> Result<User, DatabaseError> {
        validate_password(new_password, self.password_policy())
            .map_err(DatabaseError::Validation)?;

        let password_hash = hash_password(new_password).map_err(|e| {
            DatabaseError::Crypto(format!("Failed to hash password: {}", e))
        })?;

        let _ = Self::get_user_by_id_internal(conn, user_id)?;

        conn.execute(
            "UPDATE users
             SET password_hash = ?1, must_change_password = 1, failed_login_attempts = 0, locked_until = NULL, updated_at = strftime('%s','now')
             WHERE id = ?2",
            params![password_hash, user_id],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        // SECURITY FIX: Revoke all API keys when password is reset
        // This prevents compromised accounts from maintaining persistent access
        // via existing API keys after the password has been changed
        Self::revoke_user_api_keys_internal(
            conn,
            user_id,
            None, // System-initiated revocation
            "Password reset by administrator",
        )?;

        Self::get_user_by_id_internal(conn, user_id)
    }

    pub fn admin_reset_password_transactional(
        &self,
        user_id: i64,
        new_password: &str,
        audit: Option<AuditLogParams>,
    ) -> Result<User, DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        let user =
            self.admin_reset_password_with_conn(&tx, user_id, new_password)?;
        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }
        tx.commit()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        Ok(user)
    }

    // =============================================================================
    // STRING VALIDATION HELPERS
    // =============================================================================

    /// Validate a username for CRLF injection and other attacks
    ///
    /// SECURITY FIX: Prevents CRLF injection, header manipulation, and log forgery
    pub(crate) fn validate_username(
        username: &str,
    ) -> Result<(), DatabaseError> {
        // Check length (reasonable username limit)
        if username.len() > 64 {
            return Err(DatabaseError::Validation(
                "Username must be 64 characters or less".to_string(),
            ));
        }

        if username.is_empty() || username.trim().is_empty() {
            return Err(DatabaseError::Validation(
                "Username cannot be empty".to_string(),
            ));
        }

        // SECURITY: Check for CRLF injection
        if username.contains('\r') || username.contains('\n') {
            return Err(DatabaseError::Validation(
                "Username contains invalid characters (CRLF)".to_string(),
            ));
        }

        // Check for null bytes
        if username.contains('\0') {
            return Err(DatabaseError::Validation(
                "Username contains null bytes".to_string(),
            ));
        }

        // Check for other control characters
        if username.chars().any(|c| c.is_control() && c != '\t') {
            return Err(DatabaseError::Validation(
                "Username contains invalid control characters".to_string(),
            ));
        }

        // Check for dangerous characters commonly used in attacks
        let dangerous = ['<', '>', '"', '\'', '`', '&', '|', ';', '$', '\\'];
        if username.chars().any(|c| dangerous.contains(&c)) {
            return Err(DatabaseError::Validation(
                "Username contains invalid characters. Only alphanumeric, underscore, hyphen, period, and @ allowed".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate a description field for CRLF injection
    ///
    /// SECURITY FIX: Prevents CRLF injection in description fields
    pub(crate) fn validate_description(
        description: Option<&str>,
    ) -> Result<(), DatabaseError> {
        if let Some(desc) = description {
            // Check length
            if desc.len() > 500 {
                return Err(DatabaseError::Validation(
                    "Description must be 500 characters or less".to_string(),
                ));
            }

            // SECURITY: Check for CRLF injection
            if desc.contains('\r') || desc.contains('\n') {
                return Err(DatabaseError::Validation(
                    "Description contains invalid characters (CRLF)"
                        .to_string(),
                ));
            }

            // Check for null bytes
            if desc.contains('\0') {
                return Err(DatabaseError::Validation(
                    "Description contains null bytes".to_string(),
                ));
            }

            // Check for excessive control characters (allow tab)
            if desc.chars().any(|c| c.is_control() && c != '\t') {
                return Err(DatabaseError::Validation(
                    "Description contains invalid control characters"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

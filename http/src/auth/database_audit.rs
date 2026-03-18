// Ave HTTP Auth System - Audit Log and Rate Limiting Database Operations
//
// This module provides database operations for audit logging and rate limiting

use super::database::{AuthDatabase, DatabaseError};
use super::models::*;
use super::system_config::{SystemConfigKey, system_config_from_row};
use ave_actors::rusqlite::{self,
    OptionalExtension, Result as SqliteResult, TransactionBehavior, params,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Sanitize log field to prevent log injection attacks
/// Removes control characters (except space) and limits length
fn sanitize_log_field(input: &str, max_length: usize) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_length)
        .collect()
}

fn append_audit_log_filters(
    query: &AuditLogQuery,
    sql: &mut String,
    params_vec: &mut Vec<Box<dyn rusqlite::ToSql>>,
) {
    if let Some(uid) = query.user_id {
        sql.push_str(" AND user_id = ?");
        params_vec.push(Box::new(uid));
    }

    if let Some(ref api_key_id) = query.api_key_id {
        sql.push_str(" AND api_key_id = ?");
        params_vec.push(Box::new(api_key_id.clone()));
    }

    if let Some(ref endpoint) = query.endpoint {
        sql.push_str(" AND endpoint = ?");
        params_vec.push(Box::new(endpoint.clone()));
    }

    if let Some(ref method) = query.http_method {
        sql.push_str(" AND http_method = ?");
        params_vec.push(Box::new(method.clone()));
    }

    if let Some(ref ip) = query.ip_address {
        sql.push_str(" AND ip_address = ?");
        params_vec.push(Box::new(ip.clone()));
    }

    if let Some(ref ua) = query.user_agent {
        sql.push_str(" AND user_agent = ?");
        params_vec.push(Box::new(ua.clone()));
    }

    if let Some(success) = query.success {
        sql.push_str(" AND success = ?");
        params_vec.push(Box::new(success));
    }

    if let Some(start) = query.start_timestamp {
        sql.push_str(" AND timestamp >= ?");
        params_vec.push(Box::new(start));
    }

    if let Some(end) = query.end_timestamp {
        sql.push_str(" AND timestamp <= ?");
        params_vec.push(Box::new(end));
    }

    if let Some(exclude_uid) = query.exclude_user_id {
        sql.push_str(" AND (user_id IS NULL OR user_id != ?)");
        params_vec.push(Box::new(exclude_uid));
    }

    if let Some(ref exclude_api_key) = query.exclude_api_key_id {
        sql.push_str(" AND (api_key_id IS NULL OR api_key_id != ?)");
        params_vec.push(Box::new(exclude_api_key.clone()));
    }

    if let Some(ref exclude_ip) = query.exclude_ip_address {
        sql.push_str(" AND (ip_address IS NULL OR ip_address != ?)");
        params_vec.push(Box::new(exclude_ip.clone()));
    }

    if let Some(ref exclude_endpoint) = query.exclude_endpoint {
        sql.push_str(" AND (endpoint IS NULL OR endpoint != ?)");
        params_vec.push(Box::new(exclude_endpoint.clone()));
    }
}

// =============================================================================
// AUDIT LOG OPERATIONS
// =============================================================================

/// Parameters for creating an audit log entry
pub struct AuditLogParams<'a> {
    pub user_id: Option<i64>,
    pub api_key_id: Option<&'a str>, // UUID
    pub action_type: &'a str,
    pub endpoint: Option<&'a str>,
    pub http_method: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub details: Option<&'a str>,
    pub success: bool,
    pub error_message: Option<&'a str>,
}

/// Parameters for logging an API request
pub struct ApiRequestParams<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub request_id: &'a str,
    pub success: bool,
    pub error_message: Option<&'a str>,
}

impl AuthDatabase {
    pub(crate) fn create_audit_log_with_conn(
        conn: &rusqlite::Connection,
        audit_enabled: bool,
        params: AuditLogParams,
    ) -> Result<i64, DatabaseError> {
        if !audit_enabled {
            return Ok(0);
        }

        // SECURITY FIX: Sanitize user-controlled fields to prevent log injection
        let sanitized_user_agent =
            params.user_agent.map(|ua| sanitize_log_field(ua, 500));
        let sanitized_ip =
            params.ip_address.map(|ip| sanitize_log_field(ip, 100));
        let sanitized_endpoint =
            params.endpoint.map(|ep| sanitize_log_field(ep, 500));
        let sanitized_details =
            params.details.map(|d| sanitize_log_field(d, 2000));
        let sanitized_error =
            params.error_message.map(|e| sanitize_log_field(e, 1000));
        let validated_api_key_id = match params.api_key_id {
            Some(api_key_id) => {
                let exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE id = ?1)",
                        params![api_key_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| DatabaseError::Query(e.to_string()))?;
                exists.then_some(api_key_id)
            }
            None => None,
        };

        conn.execute(
            "INSERT INTO audit_logs (
                user_id, api_key_id, action_type,
                endpoint, http_method, ip_address, user_agent, request_id,
                details, success, error_message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                params.user_id,
                validated_api_key_id,
                params.action_type,
                sanitized_endpoint.as_deref(),
                params.http_method,
                sanitized_ip.as_deref(),
                sanitized_user_agent.as_deref(),
                params.request_id,
                sanitized_details.as_deref(),
                params.success,
                sanitized_error.as_deref()
            ],
        )
        .map_err(|e| DatabaseError::Insert(e.to_string()))?;

        Ok(conn.last_insert_rowid())
    }

    /// Create an audit log entry
    pub fn create_audit_log(
        &self,
        params: AuditLogParams,
    ) -> Result<i64, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::create_audit_log_with_conn(&conn, self.audit_enabled(), params)
    }

    /// Log an API request if audit logging of requests is enabled
    pub fn log_api_request(
        &self,
        ctx: &crate::auth::models::AuthContext,
        req_params: ApiRequestParams,
    ) -> Result<i64, DatabaseError> {
        // SECURITY: Always log all API requests for full traceability
        // LRU cleanup prevents unbounded growth (see cleanup_excess_audit_logs)
        self.create_audit_log(AuditLogParams {
            user_id: Some(ctx.user_id),
            api_key_id: Some(&ctx.api_key_id),
            action_type: "api_request",
            endpoint: Some(req_params.path),
            http_method: Some(req_params.method),
            ip_address: req_params.ip_address,
            user_agent: req_params.user_agent,
            request_id: Some(req_params.request_id),
            details: None,
            success: req_params.success,
            error_message: req_params.error_message,
        })
    }

    /// Query audit logs
    pub fn query_audit_logs(
        &self,
        query: &AuditLogQuery,
    ) -> Result<Vec<AuditLog>, DatabaseError> {
        Ok(self.query_audit_logs_page(query)?.items)
    }

    pub fn query_audit_logs_page(
        &self,
        query: &AuditLogQuery,
    ) -> Result<AuditLogPage, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut sql = String::from(
            "SELECT id, timestamp, user_id, api_key_id, action_type,
                    endpoint, http_method, ip_address, user_agent,
                    request_id, details, success, error_message
             FROM audit_logs
             WHERE 1=1",
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        append_audit_log_filters(query, &mut sql, &mut params_vec);

        sql.push_str(" ORDER BY timestamp DESC");

        let max_limit = self.audit_logs_max_limit();
        let default_limit = self.audit_logs_default_limit();

        let limit = match query.limit {
            Some(l) if l > 0 && l <= max_limit => l,
            Some(l) if l <= 0 => {
                return Err(DatabaseError::Validation(format!(
                    "Limit must be positive (got {})",
                    l
                )));
            }
            Some(l) => {
                return Err(DatabaseError::Validation(format!(
                    "Limit must not exceed {} (got {})",
                    max_limit, l
                )));
            }
            None => default_limit,
        };

        let offset = match query.offset {
            Some(o) if o >= 0 => o,
            Some(o) => {
                return Err(DatabaseError::Validation(format!(
                    "Offset must be non-negative (got {})",
                    o
                )));
            }
            None => 0,
        };

        sql.push_str(" LIMIT ?");
        params_vec.push(Box::new(limit));

        sql.push_str(" OFFSET ?");
        params_vec.push(Box::new(offset));

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut count_sql =
            String::from("SELECT COUNT(*) FROM audit_logs WHERE 1=1");
        let mut count_params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        append_audit_log_filters(query, &mut count_sql, &mut count_params_vec);
        let count_params_refs: Vec<&dyn rusqlite::ToSql> =
            count_params_vec.iter().map(|p| p.as_ref()).collect();
        let total: i64 = conn
            .query_row(&count_sql, count_params_refs.as_slice(), |row| {
                row.get(0)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let logs = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(AuditLog {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    user_id: row.get(2)?,
                    api_key_id: row.get(3)?,
                    action_type: row.get(4)?,
                    endpoint: row.get(5)?,
                    http_method: row.get(6)?,
                    ip_address: row.get(7)?,
                    user_agent: row.get(8)?,
                    request_id: row.get(9)?,
                    details: row.get(10)?,
                    success: row.get(11)?,
                    error_message: row.get(12)?,
                })
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        drop(stmt);
        drop(conn);

        Ok(AuditLogPage {
            has_more: offset + (logs.len() as i64) < total,
            items: logs,
            limit,
            offset,
            total,
        })
    }

    /// Delete audit logs older than retention period
    pub fn cleanup_old_audit_logs(
        &self,
        retention_days: u32,
    ) -> Result<usize, DatabaseError> {
        if retention_days == 0 {
            return Ok(0); // Keep forever
        }

        let cutoff_timestamp = Self::now() - (retention_days as i64 * 86400);
        let conn = self.lock_maintenance_conn()?;
        let mut total_deleted = 0usize;
        let batch_size = self.audit_cleanup_batch_size();

        loop {
            let deleted = conn
                .execute(
                    "DELETE FROM audit_logs
                     WHERE id IN (
                        SELECT id
                        FROM audit_logs
                        WHERE timestamp < ?1
                        ORDER BY timestamp ASC
                        LIMIT ?2
                     )",
                    params![cutoff_timestamp, batch_size],
                )
                .map_err(|e| DatabaseError::Delete(e.to_string()))?;

            total_deleted += deleted;

            if deleted < batch_size as usize {
                break;
            }
        }

        Ok(total_deleted)
    }

    /// Delete oldest audit logs if count exceeds max_entries (LRU eviction)
    pub fn cleanup_excess_audit_logs(
        &self,
        max_entries: u32,
    ) -> Result<usize, DatabaseError> {
        if max_entries == 0 {
            return Ok(0); // Unlimited
        }

        let conn = self.lock_maintenance_conn()?;

        // Count current entries
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_logs", [], |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if count <= max_entries as i64 {
            return Ok(0); // Under limit
        }

        // Delete oldest entries to bring count down to max_entries
        let to_delete = count - max_entries as i64;

        let mut total_deleted = 0usize;
        let mut remaining = to_delete;
        let batch_limit = self.audit_cleanup_batch_size();

        while remaining > 0 {
            let batch_size = remaining.min(batch_limit);
            let deleted = conn
                .execute(
                    "DELETE FROM audit_logs
                     WHERE id IN (
                        SELECT id
                        FROM audit_logs
                        ORDER BY timestamp ASC
                        LIMIT ?1
                     )",
                    params![batch_size],
                )
                .map_err(|e| DatabaseError::Delete(e.to_string()))?;

            total_deleted += deleted;
            remaining -= deleted as i64;

            if deleted == 0 {
                break;
            }
        }

        Ok(total_deleted)
    }

    /// Get audit log statistics
    // conn is captured by the top_n closure, so it cannot be dropped early
    pub fn get_audit_stats(
        &self,
        days: u32,
    ) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.lock_conn()?;

        let cutoff = Self::now() - (days as i64 * 86400);

        // Total logs
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Success/failure counts
        let success_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?1 AND success = 1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let failure_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?1 AND success = 0",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Common helper to fetch top-N aggregated counts
        let top_n = |sql: &str| -> Result<Vec<(String, i64)>, DatabaseError> {
            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(params![cutoff], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))
        };

        let top_actions = top_n(
            "SELECT action_type, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1
             GROUP BY action_type
             ORDER BY count DESC
             LIMIT 10",
        )?;

        let top_users = top_n(
            "SELECT CAST(user_id AS TEXT) as user_id, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1 AND user_id IS NOT NULL
             GROUP BY user_id
             ORDER BY count DESC
             LIMIT 10",
        )?;

        let top_api_keys = top_n(
            "SELECT CAST(api_key_id AS TEXT) as api_key_id, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1 AND api_key_id IS NOT NULL
             GROUP BY api_key_id
             ORDER BY count DESC
             LIMIT 10",
        )?;

        let top_endpoints = top_n(
            "SELECT endpoint, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1 AND endpoint IS NOT NULL
             GROUP BY endpoint
             ORDER BY count DESC
             LIMIT 10",
        )?;

        let top_methods = top_n(
            "SELECT http_method, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1 AND http_method IS NOT NULL
             GROUP BY http_method
             ORDER BY count DESC
             LIMIT 10",
        )?;

        let top_ips = top_n(
            "SELECT ip_address, COUNT(*) as count
             FROM audit_logs
             WHERE timestamp >= ?1 AND ip_address IS NOT NULL
             GROUP BY ip_address
             ORDER BY count DESC
             LIMIT 10",
        )?;

        Ok(serde_json::json!({
            "total_logs": total,
            "success_count": success_count,
            "failure_count": failure_count,
            "success_rate": if total > 0 { (success_count as f64 / total as f64) * 100.0 } else { 0.0 },
            "top_action_types": top_actions,
            "top_users": top_users,
            "top_api_keys": top_api_keys,
            "top_endpoints": top_endpoints,
            "top_http_methods": top_methods,
            "top_ip_addresses": top_ips,
        }))
    }
}

// =============================================================================
// RATE LIMITING OPERATIONS
// =============================================================================

impl AuthDatabase {
    pub(crate) fn check_rate_limit_with_conn(
        &self,
        conn: &rusqlite::Connection,
        api_key_id: Option<&str>, // UUID
        ip_address: Option<&str>,
        endpoint: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        if !self.rate_limit_enabled() {
            return Ok(true);
        }

        let api_key_id = if self.rate_limit_limit_by_key() {
            api_key_id
        } else {
            None
        };
        let ip_address = if self.rate_limit_limit_by_ip() {
            ip_address
        } else {
            None
        };

        let (max_requests, window_seconds) =
            self.get_endpoint_rate_limit(endpoint)?;

        let now = Self::now();
        let window_start = now - window_seconds;

        let select_where = match (api_key_id, ip_address) {
            (Some(_), Some(_)) => {
                "WHERE api_key_id = ?1 AND ip_address = ?2 AND endpoint = ?3 AND window_start >= ?4"
            }
            (Some(_), None) => {
                "WHERE api_key_id = ?1 AND ip_address IS NULL AND endpoint = ?3 AND window_start >= ?4"
            }
            (None, Some(_)) => {
                "WHERE api_key_id IS NULL AND ip_address = ?2 AND endpoint = ?3 AND window_start >= ?4"
            }
            (None, None) => {
                "WHERE api_key_id IS NULL AND ip_address IS NULL AND endpoint = ?3 AND window_start >= ?4"
            }
        };

        let sum_query = format!(
            "SELECT COALESCE(SUM(request_count), 0) FROM rate_limits {}",
            select_where
        );
        let current_count: i64 = conn
            .query_row(
                &sum_query,
                params![api_key_id, ip_address, endpoint, window_start],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if current_count >= max_requests as i64 {
            return Err(DatabaseError::RateLimitExceeded(format!(
                "Rate limit exceeded: {} requests in {} seconds",
                max_requests, window_seconds
            )));
        }

        let latest_query = format!(
            "SELECT id FROM rate_limits {} ORDER BY window_start DESC, id DESC LIMIT 1",
            select_where
        );
        let latest_row_id: Option<i64> = conn
            .query_row(
                &latest_query,
                params![api_key_id, ip_address, endpoint, window_start],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if let Some(row_id) = latest_row_id {
            conn.execute(
                "UPDATE rate_limits
                 SET request_count = request_count + 1, last_request_at = ?1
                 WHERE id = ?2",
                params![now, row_id],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        } else {
            conn.execute(
                "INSERT INTO rate_limits (api_key_id, ip_address, endpoint, window_start, request_count, last_request_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![api_key_id, ip_address, endpoint, now, now],
            )
            .map_err(|e| DatabaseError::Insert(e.to_string()))?;
        }

        Ok(true)
    }

    /// Check rate limit and record request
    pub fn check_rate_limit(
        &self,
        api_key_id: Option<&str>, // UUID
        ip_address: Option<&str>,
        endpoint: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        let mut conn = self.lock_conn()?;
        let tx_started = std::time::Instant::now();
        let result = (|| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;

            let allowed = self.check_rate_limit_with_conn(
                &tx, api_key_id, ip_address, endpoint,
            )?;

            tx.commit()
                .map_err(|e| DatabaseError::Update(e.to_string()))?;

            Ok(allowed)
        })();
        self.record_transaction_duration(
            "check_rate_limit",
            tx_started.elapsed(),
        );
        result
    }

    /// Get endpoint-specific rate limit configuration
    /// Returns (max_requests, window_seconds) tuple
    fn get_endpoint_rate_limit(
        &self,
        endpoint: Option<&str>,
    ) -> Result<(u32, i64), DatabaseError> {
        // If no endpoint specified, use defaults
        let Some(endpoint_path) = endpoint else {
            return Ok(self.rate_limit_defaults());
        };

        let (_, default_window_seconds) = self.rate_limit_defaults();

        // Check if this endpoint has a specific configuration
        let sensitive_endpoints = self.rate_limit_sensitive_endpoints()?;
        for endpoint_config in &sensitive_endpoints {
            if endpoint_config.endpoint == endpoint_path {
                let window = endpoint_config
                    .window_seconds
                    .unwrap_or(default_window_seconds);
                return Ok((endpoint_config.max_requests, window));
            }
        }

        // No specific config found, use defaults
        Ok(self.rate_limit_defaults())
    }

    /// Cleanup old rate limit entries
    pub fn cleanup_rate_limits(&self) -> Result<usize, DatabaseError> {
        let cutoff = Self::now() - self.rate_limit_cleanup_interval_seconds();
        let conn = self.lock_maintenance_conn()?;
        let mut total_deleted = 0usize;
        let batch_size = self.rate_limit_cleanup_batch_size();

        loop {
            let deleted = conn
                .execute(
                    "DELETE FROM rate_limits
                     WHERE id IN (
                        SELECT id
                        FROM rate_limits
                        WHERE window_start < ?1
                        ORDER BY window_start ASC
                        LIMIT ?2
                     )",
                    params![cutoff, batch_size],
                )
                .map_err(|e| DatabaseError::Delete(e.to_string()))?;

            total_deleted += deleted;

            if deleted < batch_size as usize {
                break;
            }
        }

        Ok(total_deleted)
    }

    /// Get detailed rate limit breakdown by API key, IP, and endpoint
    // Multiple stmt rebindings prevent early conn drop without major restructuring
    pub fn get_rate_limit_details(
        &self,
        hours: u32,
    ) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.lock_conn()?;

        let cutoff = Self::now() - (hours as i64 * 3600);

        // Get top API keys by request count
        let mut stmt = conn
            .prepare(
                "SELECT
                    rl.api_key_id,
                    ak.name as key_name,
                    ak.user_id,
                    u.username,
                    SUM(rl.request_count) as total_requests,
                    MAX(rl.last_request_at) as last_request
                 FROM rate_limits rl
                 LEFT JOIN api_keys ak ON rl.api_key_id = ak.id
                 LEFT JOIN users u ON ak.user_id = u.id
                 WHERE rl.window_start >= ?1 AND rl.api_key_id IS NOT NULL
                 GROUP BY rl.api_key_id
                 ORDER BY total_requests DESC
                 LIMIT 50",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let by_api_key: Vec<serde_json::Value> = stmt
            .query_map(params![cutoff], |row| {
                Ok(serde_json::json!({
                    "api_key_id": row.get::<_, Option<String>>(0)?,
                    "key_name": row.get::<_, Option<String>>(1)?,
                    "user_id": row.get::<_, Option<i64>>(2)?,
                    "username": row.get::<_, Option<String>>(3)?,
                    "total_requests": row.get::<_, i64>(4)?,
                    "last_request_at": row.get::<_, Option<i64>>(5)?.map(format_ts),
                }))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Get top IPs by request count
        let mut stmt = conn
            .prepare(
                "SELECT
                    rl.ip_address,
                    SUM(rl.request_count) as total_requests,
                    MAX(rl.last_request_at) as last_request,
                    COUNT(DISTINCT rl.api_key_id) as unique_keys
                 FROM rate_limits rl
                 WHERE rl.window_start >= ?1 AND rl.ip_address IS NOT NULL
                 GROUP BY rl.ip_address
                 ORDER BY total_requests DESC
                 LIMIT 50",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let by_ip: Vec<serde_json::Value> = stmt
            .query_map(params![cutoff], |row| {
                Ok(serde_json::json!({
                    "ip_address": row.get::<_, Option<String>>(0)?,
                    "total_requests": row.get::<_, i64>(1)?,
                    "last_request_at": row.get::<_, Option<i64>>(2)?.map(format_ts),
                    "unique_api_keys": row.get::<_, i64>(3)?,
                }))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Get top endpoints by request count
        let mut stmt = conn
            .prepare(
                "SELECT
                    rl.endpoint,
                    SUM(rl.request_count) as total_requests,
                    MAX(rl.last_request_at) as last_request
                 FROM rate_limits rl
                 WHERE rl.window_start >= ?1 AND rl.endpoint IS NOT NULL
                 GROUP BY rl.endpoint
                 ORDER BY total_requests DESC
                 LIMIT 50",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let by_endpoint: Vec<serde_json::Value> = stmt
            .query_map(params![cutoff], |row| {
                Ok(serde_json::json!({
                    "endpoint": row.get::<_, Option<String>>(0)?,
                    "total_requests": row.get::<_, i64>(1)?,
                    "last_request_at": row.get::<_, Option<i64>>(2)?.map(format_ts),
                }))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Get IP + Endpoint breakdown (what endpoint is each IP accessing)
        let mut stmt = conn
            .prepare(
                "SELECT
                    rl.ip_address,
                    rl.endpoint,
                    SUM(rl.request_count) as total_requests,
                    MAX(rl.last_request_at) as last_request,
                    COUNT(DISTINCT rl.api_key_id) as unique_keys
                 FROM rate_limits rl
                 WHERE rl.window_start >= ?1
                   AND rl.ip_address IS NOT NULL
                   AND rl.endpoint IS NOT NULL
                 GROUP BY rl.ip_address, rl.endpoint
                 ORDER BY total_requests DESC
                 LIMIT 100",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let by_ip_endpoint: Vec<serde_json::Value> = stmt
            .query_map(params![cutoff], |row| {
                Ok(serde_json::json!({
                    "ip_address": row.get::<_, Option<String>>(0)?,
                    "endpoint": row.get::<_, Option<String>>(1)?,
                    "total_requests": row.get::<_, i64>(2)?,
                    "last_request_at": row.get::<_, Option<i64>>(3)?.map(format_ts),
                    "unique_api_keys": row.get::<_, i64>(4)?,
                }))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        // Get total requests in period
        let total_requests: i64 = conn
            .query_row(
                "SELECT SUM(request_count) FROM rate_limits WHERE window_start >= ?1",
                params![cutoff],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let (max_requests, window_seconds) = self.rate_limit_defaults();

        Ok(serde_json::json!({
            "total_requests": total_requests,
            "window_seconds": window_seconds,
            "max_requests_per_window": max_requests,
            "by_api_key": by_api_key,
            "by_ip": by_ip,
            "by_endpoint": by_endpoint,
            "by_ip_endpoint": by_ip_endpoint,
        }))
    }
}

fn format_ts(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts).map_or_else(
        |_| ts.to_string(),
        |dt| dt.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()),
    )
}

// =============================================================================
// SYSTEM CONFIG OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Internal: Get system config value without acquiring lock
    fn get_system_config_internal(
        conn: &rusqlite::Connection,
        key: &str,
    ) -> Result<SystemConfig, DatabaseError> {
        let row = conn
            .query_row(
                "SELECT key, value, description, updated_at, updated_by
                 FROM system_config
                 WHERE key = ?1",
                params![key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        system_config_from_row(&row.0, &row.1, row.2, row.3, row.4)
    }

    /// List all system config
    pub fn list_system_config(
        &self,
    ) -> Result<Vec<SystemConfig>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT key, value, description, updated_at, updated_by
             FROM system_config
             ORDER BY key",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        let configs = rows
            .into_iter()
            .map(|(key, value, description, updated_at, updated_by)| {
                system_config_from_row(
                    &key,
                    &value,
                    description,
                    updated_at,
                    updated_by,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);

        Ok(configs)
    }

    /// Update system config
    pub fn update_system_config(
        &self,
        key: &str,
        value: &str,
        updated_by: Option<i64>,
    ) -> Result<SystemConfig, DatabaseError> {
        let key_id = SystemConfigKey::parse(key)?;
        let typed_value = key_id.parse_persisted_value(value)?;
        key_id.validate_value(&typed_value)?;
        let persisted_value = key_id.serialize_value(&typed_value)?;

        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE system_config SET value = ?1, updated_by = ?2, updated_at = strftime('%s', 'now') WHERE key = ?3",
            params![persisted_value, updated_by, key],
        ).map_err(|e| DatabaseError::Update(e.to_string()))?;

        self.apply_runtime_system_config_value(key_id, &typed_value)?;

        let result = Self::get_system_config_internal(&conn, key);
        drop(conn);
        result
    }

    pub fn update_system_config_transactional(
        &self,
        key: &str,
        value: &str,
        updated_by: Option<i64>,
        audit: Option<AuditLogParams>,
    ) -> Result<SystemConfig, DatabaseError> {
        if audit.is_none() {
            return self.update_system_config(key, value, updated_by);
        }

        let key_id = SystemConfigKey::parse(key)?;
        let typed_value = key_id.parse_persisted_value(value)?;
        key_id.validate_value(&typed_value)?;
        let persisted_value = key_id.serialize_value(&typed_value)?;

        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;

        tx.execute(
            "UPDATE system_config SET value = ?1, updated_by = ?2, updated_at = strftime('%s', 'now') WHERE key = ?3",
            params![persisted_value, updated_by, key],
        ).map_err(|e| DatabaseError::Update(e.to_string()))?;

        if let Some(audit) = audit {
            Self::create_audit_log_with_conn(&tx, self.audit_enabled(), audit)?;
        }

        let result = Self::get_system_config_internal(&tx, key)?;

        tx.commit()
            .map_err(|e| DatabaseError::Update(e.to_string()))?;

        self.apply_runtime_system_config_value(key_id, &typed_value)?;

        Ok(result)
    }

    pub fn update_system_config_typed(
        &self,
        key: &str,
        value: &SystemConfigValue,
        updated_by: Option<i64>,
    ) -> Result<SystemConfig, DatabaseError> {
        let key_id = SystemConfigKey::parse(key)?;
        let persisted_value = key_id.serialize_value(value)?;
        self.update_system_config(key, &persisted_value, updated_by)
    }

    pub fn update_system_config_typed_transactional(
        &self,
        key: &str,
        value: &SystemConfigValue,
        updated_by: Option<i64>,
        audit: Option<AuditLogParams>,
    ) -> Result<SystemConfig, DatabaseError> {
        let key_id = SystemConfigKey::parse(key)?;
        let persisted_value = key_id.serialize_value(value)?;
        self.update_system_config_transactional(
            key,
            &persisted_value,
            updated_by,
            audit,
        )
    }
}

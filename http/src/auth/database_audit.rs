// Ave HTTP Auth System - Audit Log and Rate Limiting Database Operations
//
// This module provides database operations for audit logging and rate limiting

use super::database::{AuthDatabase, DatabaseError};
use super::models::*;
use rusqlite::{OptionalExtension, Result as SqliteResult, params};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

// =============================================================================
// AUDIT LOG OPERATIONS
// =============================================================================

/// Parameters for creating an audit log entry
pub struct AuditLogParams<'a> {
    pub user_id: Option<i64>,
    pub api_key_id: Option<&'a str>,  // UUID
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
    /// Create an audit log entry
    pub fn create_audit_log(
        &self,
        params: AuditLogParams,
    ) -> Result<i64, DatabaseError> {
        // Respect global audit toggle
        if !self.config.session.audit_enable {
            return Ok(0); // Auditing disabled
        }

        let conn = self.lock_conn()?;

        conn.execute(
            "INSERT INTO audit_logs (
                user_id, api_key_id, action_type,
                endpoint, http_method, ip_address, user_agent, request_id,
                details, success, error_message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                params.user_id,
                params.api_key_id,
                params.action_type,
                params.endpoint,
                params.http_method,
                params.ip_address,
                params.user_agent,
                params.request_id,
                params.details,
                params.success,
                params.error_message
            ],
        )
        .map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        Ok(conn.last_insert_rowid())
    }

    /// Log an API request if audit logging of requests is enabled
    pub fn log_api_request(
        &self,
        ctx: &crate::auth::models::AuthContext,
        req_params: ApiRequestParams,
    ) -> Result<i64, DatabaseError> {
        if !self.config.session.log_all_requests {
            return Ok(0);
        }

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
        let conn = self.lock_conn()?;

        let mut sql = String::from(
            "SELECT id, timestamp, user_id, api_key_id, action_type,
                    endpoint, http_method, ip_address, user_agent,
                    request_id, details, success, error_message
             FROM audit_logs
             WHERE 1=1",
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(uid) = query.user_id {
            sql.push_str(" AND user_id = ?");
            params_vec.push(Box::new(uid));
        }

        if let Some(ref api_key_id) = query.api_key_id {
            sql.push_str(" AND api_key_id = ?");
            params_vec.push(Box::new(api_key_id.as_str()));
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

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params_vec.push(Box::new(limit));
        }

        if let Some(offset) = query.offset {
            sql.push_str(" OFFSET ?");
            params_vec.push(Box::new(offset));
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

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
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(logs)
    }

    /// Delete audit logs older than retention period
    pub fn cleanup_old_audit_logs(
        &self,
        retention_days: u32,
    ) -> Result<usize, DatabaseError> {
        if retention_days == 0 {
            return Ok(0); // Keep forever
        }

        let conn = self.lock_conn()?;

        let cutoff_timestamp = Self::now() - (retention_days as i64 * 86400);

        let deleted = conn
            .execute(
                "DELETE FROM audit_logs WHERE timestamp < ?1",
                params![cutoff_timestamp],
            )
            .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        Ok(deleted)
    }

    /// Get audit log statistics
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
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        // Success/failure counts
        let success_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?1 AND success = 1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let failure_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ?1 AND success = 0",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        // Common helper to fetch top-N aggregated counts
        let top_n = |sql: &str| -> Result<Vec<(String, i64)>, DatabaseError> {
            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;
            stmt.query_map(params![cutoff], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))
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
    /// Check rate limit and record request
    pub fn check_rate_limit(
        &self,
        api_key_id: Option<&str>,  // UUID
        ip_address: Option<&str>,
        endpoint: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        if !self.config.rate_limit.enable {
            return Ok(true); // Rate limiting disabled
        }

        // Respect configuration for which dimensions participate in the limit
        let api_key_id = if self.config.rate_limit.limit_by_key {
            api_key_id
        } else {
            None
        };
        let ip_address = if self.config.rate_limit.limit_by_ip {
            ip_address
        } else {
            None
        };

        let conn = self.lock_conn()?;

        let now = Self::now();
        let window_start = now - self.config.rate_limit.window_seconds;

        // Try to get existing rate limit entry
        let current_count: Option<i64> = conn
            .query_row(
                "SELECT request_count FROM rate_limits
                 WHERE api_key_id IS ?1 AND ip_address IS ?2 AND endpoint IS ?3
                   AND window_start >= ?4",
                params![api_key_id, ip_address, endpoint, window_start],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let max_requests = self.config.rate_limit.max_requests as i64;

        if let Some(count) = current_count {
            if count >= max_requests {
                return Err(DatabaseError::RateLimitExceeded(format!(
                    "Rate limit exceeded: {} requests in {} seconds",
                    max_requests, self.config.rate_limit.window_seconds
                )));
            }

            // Increment counter
            conn.execute(
                "UPDATE rate_limits
                 SET request_count = request_count + 1, last_request_at = ?1
                 WHERE api_key_id IS ?2 AND ip_address IS ?3 AND endpoint IS ?4
                   AND window_start >= ?5",
                params![now, api_key_id, ip_address, endpoint, window_start],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        } else {
            // Create new entry
            conn.execute(
                "INSERT INTO rate_limits (api_key_id, ip_address, endpoint, window_start, request_count, last_request_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![api_key_id, ip_address, endpoint, now, now],
            ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;
        }

        Ok(true)
    }

    /// Cleanup old rate limit entries
    pub fn cleanup_rate_limits(&self) -> Result<usize, DatabaseError> {
        let conn = self.lock_conn()?;

        let cutoff =
            Self::now() - self.config.rate_limit.cleanup_interval_seconds;

        let deleted = conn
            .execute(
                "DELETE FROM rate_limits WHERE window_start < ?1",
                params![cutoff],
            )
            .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        Ok(deleted)
    }

    /// Get rate limit stats for a user
    pub fn get_rate_limit_stats(
        &self,
        api_key_id: Option<&str>,  // UUID
        hours: u32,
    ) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.lock_conn()?;

        let cutoff = Self::now() - (hours as i64 * 3600);

        let mut stmt = conn
            .prepare(
                "SELECT window_start, SUM(request_count) as total_requests
             FROM rate_limits
             WHERE (api_key_id IS ?1 OR ?1 IS NULL) AND window_start >= ?2
             GROUP BY window_start
             ORDER BY window_start DESC
             LIMIT 100",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let data: Vec<(i64, i64)> = stmt
            .query_map(params![api_key_id, cutoff], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let total_requests: i64 = data.iter().map(|(_, count)| count).sum();
        let requests_per_window: Vec<(String, i64)> = data
            .into_iter()
            .map(|(ts, count)| (format_ts(ts), count))
            .collect();

        Ok(serde_json::json!({
            "total_requests": total_requests,
            "window_seconds": self.config.rate_limit.window_seconds,
            "max_requests_per_window": self.config.rate_limit.max_requests,
            "requests_per_window": requests_per_window,
        }))
    }
}

fn format_ts(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| ts.to_string())
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
        conn.query_row(
            "SELECT key, value, description, updated_at, updated_by
             FROM system_config
             WHERE key = ?1",
            params![key],
            |row| {
                Ok(SystemConfig {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    description: row.get(2)?,
                    updated_at: row.get(3)?,
                    updated_by: row.get(4)?,
                })
            },
        )
        .map_err(|e| DatabaseError::QueryError(e.to_string()))
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
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let configs = stmt
            .query_map([], |row| {
                Ok(SystemConfig {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    description: row.get(2)?,
                    updated_at: row.get(3)?,
                    updated_by: row.get(4)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(configs)
    }

    /// Update system config
    pub fn update_system_config(
        &self,
        key: &str,
        value: &str,
        updated_by: Option<i64>,
    ) -> Result<SystemConfig, DatabaseError> {
        let conn = self.lock_conn()?;

        conn.execute(
            "UPDATE system_config SET value = ?1, updated_by = ?2 WHERE key = ?3",
            params![value, updated_by, key],
        ).map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Self::get_system_config_internal(&conn, key)
    }
}

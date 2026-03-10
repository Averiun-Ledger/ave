// Ave HTTP Auth System - Usage Plans and Monthly Quotas
//
// This module provides quota and plan management for API keys.

use super::database::{AuthDatabase, DatabaseError};
use super::models::{ApiKeyQuotaStatus, QuotaExtensionInfo, UsagePlan};
use rusqlite::{OptionalExtension, params};
use time::OffsetDateTime;

const MAX_PLAN_ID_LEN: usize = 64;
const MAX_PLAN_NAME_LEN: usize = 100;

impl AuthDatabase {
    fn current_usage_month() -> String {
        let now = OffsetDateTime::now_utc();
        let month_num: u8 = now.month().into();
        format!("{:04}-{:02}", now.year(), month_num)
    }

    fn validate_plan_id(plan_id: &str) -> Result<(), DatabaseError> {
        if plan_id.is_empty() {
            return Err(DatabaseError::Validation(
                "Plan id cannot be empty".to_string(),
            ));
        }

        if plan_id.len() > MAX_PLAN_ID_LEN {
            return Err(DatabaseError::Validation(format!(
                "Plan id must be {} characters or less",
                MAX_PLAN_ID_LEN
            )));
        }

        if !plan_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(DatabaseError::Validation(
                "Plan id can only contain letters, numbers, underscore, and hyphen"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn validate_plan_name(name: &str) -> Result<(), DatabaseError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(DatabaseError::Validation(
                "Plan name cannot be empty".to_string(),
            ));
        }

        if trimmed.len() > MAX_PLAN_NAME_LEN {
            return Err(DatabaseError::Validation(format!(
                "Plan name must be {} characters or less",
                MAX_PLAN_NAME_LEN
            )));
        }

        if trimmed.chars().any(|c| c.is_control()) {
            return Err(DatabaseError::Validation(
                "Plan name contains invalid control characters".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_usage_month(usage_month: &str) -> Result<(), DatabaseError> {
        let bytes = usage_month.as_bytes();
        if bytes.len() != 7 || bytes[4] != b'-' {
            return Err(DatabaseError::Validation(
                "usage_month must use YYYY-MM format".to_string(),
            ));
        }

        let year_str = std::str::from_utf8(&bytes[0..4]).map_err(|_| {
            DatabaseError::Validation("Invalid usage month year".to_string())
        })?;
        let month_str = std::str::from_utf8(&bytes[5..7]).map_err(|_| {
            DatabaseError::Validation("Invalid usage month month".to_string())
        })?;

        let year = year_str.parse::<i32>().map_err(|_| {
            DatabaseError::Validation("Invalid usage month year".to_string())
        })?;
        let month = month_str.parse::<u8>().map_err(|_| {
            DatabaseError::Validation("Invalid usage month month".to_string())
        })?;

        if year < 1970 || !(1..=12).contains(&month) {
            return Err(DatabaseError::Validation(
                "usage_month is out of valid range".to_string(),
            ));
        }

        Ok(())
    }

    fn resolve_usage_month(
        usage_month: Option<&str>,
    ) -> Result<String, DatabaseError> {
        if let Some(month) = usage_month {
            Self::validate_usage_month(month)?;
            Ok(month.to_string())
        } else {
            Ok(Self::current_usage_month())
        }
    }

    fn is_management_key_internal(
        conn: &rusqlite::Connection,
        key_id: &str,
    ) -> Result<bool, DatabaseError> {
        conn.query_row(
            "SELECT is_management FROM api_keys WHERE id = ?1",
            params![key_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .ok_or_else(|| {
            DatabaseError::NotFound(format!("API key {} not found", key_id))
        })
    }

    fn get_usage_plan_internal(
        conn: &rusqlite::Connection,
        plan_id: &str,
    ) -> Result<UsagePlan, DatabaseError> {
        conn.query_row(
            "SELECT id, name, description, monthly_events, created_at, updated_at
             FROM usage_plans
             WHERE id = ?1",
            params![plan_id],
            |row| {
                Ok(UsagePlan {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    monthly_events: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFound(format!("Plan {} not found", plan_id)))
    }

    fn get_plan_for_key_internal(
        conn: &rusqlite::Connection,
        key_id: &str,
    ) -> Result<Option<(String, i64)>, DatabaseError> {
        conn.query_row(
            "SELECT p.id, p.monthly_events
             FROM api_key_plans kp
             INNER JOIN usage_plans p ON p.id = kp.plan_id
             WHERE kp.api_key_id = ?1",
            params![key_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|e| DatabaseError::Query(e.to_string()))
    }

    fn get_used_events_internal(
        conn: &rusqlite::Connection,
        key_id: &str,
        usage_month: &str,
    ) -> Result<i64, DatabaseError> {
        conn.query_row(
            "SELECT used_events
             FROM api_key_usage
             WHERE api_key_id = ?1 AND usage_month = ?2",
            params![key_id, usage_month],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| DatabaseError::Query(e.to_string()))
        .map(|v| v.unwrap_or(0))
    }

    fn get_extensions_total_internal(
        conn: &rusqlite::Connection,
        key_id: &str,
        usage_month: &str,
    ) -> Result<i64, DatabaseError> {
        conn.query_row(
            "SELECT COALESCE(SUM(extra_events), 0)
             FROM quota_extensions
             WHERE api_key_id = ?1 AND usage_month = ?2",
            params![key_id, usage_month],
            |row| row.get(0),
        )
        .map_err(|e| DatabaseError::Query(e.to_string()))
    }

    pub fn create_usage_plan(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        monthly_events: i64,
    ) -> Result<UsagePlan, DatabaseError> {
        Self::validate_plan_id(id)?;
        Self::validate_plan_name(name)?;

        if monthly_events < 0 {
            return Err(DatabaseError::Validation(
                "monthly_events must be >= 0".to_string(),
            ));
        }

        let conn = self.lock_conn()?;
        let now = Self::now();

        conn.execute(
            "INSERT INTO usage_plans (id, name, description, monthly_events, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name.trim(), description, monthly_events, now, now],
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                DatabaseError::Duplicate(msg)
            } else {
                DatabaseError::Insert(msg)
            }
        })?;

        let plan = Self::get_usage_plan_internal(&conn, id)?;
        drop(conn);

        Ok(plan)
    }

    pub fn get_usage_plan(&self, id: &str) -> Result<UsagePlan, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_usage_plan_internal(&conn, id)
    }

    pub fn list_usage_plans(&self) -> Result<Vec<UsagePlan>, DatabaseError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, monthly_events, created_at, updated_at
                 FROM usage_plans
                 ORDER BY monthly_events ASC, id ASC",
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let plans = stmt
            .query_map([], |row| {
                Ok(UsagePlan {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    monthly_events: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(plans)
    }

    pub fn update_usage_plan(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        monthly_events: Option<i64>,
    ) -> Result<UsagePlan, DatabaseError> {
        if let Some(name) = name {
            Self::validate_plan_name(name)?;
        }

        if let Some(limit) = monthly_events
            && limit < 0
        {
            return Err(DatabaseError::Validation(
                "monthly_events must be >= 0".to_string(),
            ));
        }

        let conn = self.lock_conn()?;

        // Ensure plan exists before update
        let _ = Self::get_usage_plan_internal(&conn, id)?;

        let mut current = Self::get_usage_plan_internal(&conn, id)?;
        if let Some(new_name) = name {
            current.name = new_name.trim().to_string();
        }
        if let Some(new_description) = description {
            current.description = Some(new_description.to_string());
        }
        if let Some(new_limit) = monthly_events {
            current.monthly_events = new_limit;
        }

        let now = Self::now();
        conn.execute(
            "UPDATE usage_plans
             SET name = ?1, description = ?2, monthly_events = ?3, updated_at = ?4
             WHERE id = ?5",
            params![
                current.name,
                current.description,
                current.monthly_events,
                now,
                id
            ],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        let plan = Self::get_usage_plan_internal(&conn, id)?;
        drop(conn);

        Ok(plan)
    }

    pub fn delete_usage_plan(&self, id: &str) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let in_use: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM api_key_plans WHERE plan_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        if in_use > 0 {
            return Err(DatabaseError::Validation(format!(
                "Cannot delete usage plan '{}' because it is assigned to {} API key(s)",
                id, in_use
            )));
        }

        let deleted = conn
            .execute("DELETE FROM usage_plans WHERE id = ?1", params![id])
            .map_err(|e| DatabaseError::Delete(e.to_string()))?;

        if deleted == 0 {
            return Err(DatabaseError::NotFound(format!(
                "Plan {} not found",
                id
            )));
        }

        Ok(())
    }

    pub fn assign_api_key_plan(
        &self,
        key_id: &str,
        plan_id: Option<&str>,
        assigned_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;
        let is_management = Self::is_management_key_internal(&conn, key_id)?;

        if is_management && plan_id.is_some() {
            return Err(DatabaseError::Validation(
                "Usage plans can only be assigned to service API keys"
                    .to_string(),
            ));
        }

        if let Some(plan_id) = plan_id {
            Self::validate_plan_id(plan_id)?;
            let _ = Self::get_usage_plan_internal(&conn, plan_id)?;

            let now = Self::now();
            conn.execute(
                "INSERT INTO api_key_plans (api_key_id, plan_id, assigned_at, assigned_by)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(api_key_id) DO UPDATE SET
                   plan_id = excluded.plan_id,
                   assigned_at = excluded.assigned_at,
                   assigned_by = excluded.assigned_by",
                params![key_id, plan_id, now, assigned_by],
            )
            .map_err(|e| DatabaseError::Update(e.to_string()))?;
        } else {
            conn.execute(
                "DELETE FROM api_key_plans WHERE api_key_id = ?1",
                params![key_id],
            )
            .map_err(|e| DatabaseError::Delete(e.to_string()))?;
        }

        Ok(())
    }

    pub fn add_quota_extension(
        &self,
        key_id: &str,
        extra_events: i64,
        usage_month: Option<&str>,
        reason: Option<&str>,
        created_by: Option<i64>,
    ) -> Result<QuotaExtensionInfo, DatabaseError> {
        if extra_events <= 0 {
            return Err(DatabaseError::Validation(
                "extra_events must be > 0".to_string(),
            ));
        }

        let usage_month = Self::resolve_usage_month(usage_month)?;

        let conn = self.lock_conn()?;
        let is_management = Self::is_management_key_internal(&conn, key_id)?;

        if is_management {
            return Err(DatabaseError::Validation(
                "Quota extensions can only be added to service API keys"
                    .to_string(),
            ));
        }

        if Self::get_plan_for_key_internal(&conn, key_id)?.is_none() {
            return Err(DatabaseError::Validation(
                "Cannot add quota extension to an API key without an assigned plan"
                    .to_string(),
            ));
        }

        let now = Self::now();
        conn.execute(
            "INSERT INTO quota_extensions (api_key_id, usage_month, extra_events, reason, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key_id, usage_month, extra_events, reason, created_by, now],
        )
        .map_err(|e| DatabaseError::Insert(e.to_string()))?;

        let id = conn.last_insert_rowid();

        let row = conn
            .query_row(
                "SELECT id, api_key_id, usage_month, extra_events, reason, created_by, created_at
                 FROM quota_extensions
                 WHERE id = ?1",
                params![id],
                |row| {
                    Ok(QuotaExtensionInfo {
                        id: row.get(0)?,
                        api_key_id: row.get(1)?,
                        usage_month: row.get(2)?,
                        extra_events: row.get(3)?,
                        reason: row.get(4)?,
                        created_by: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                },
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(row)
    }

    pub fn get_api_key_quota_status(
        &self,
        key_id: &str,
        usage_month: Option<&str>,
    ) -> Result<ApiKeyQuotaStatus, DatabaseError> {
        let usage_month = Self::resolve_usage_month(usage_month)?;

        let conn = self.lock_conn()?;
        let is_management = Self::is_management_key_internal(&conn, key_id)?;

        if is_management {
            return Ok(ApiKeyQuotaStatus {
                api_key_id: key_id.to_string(),
                usage_month,
                plan_id: None,
                plan_limit: None,
                extensions_total: 0,
                effective_limit: None,
                used_events: 0,
                remaining_events: None,
                has_quota: false,
            });
        }

        let plan_info = Self::get_plan_for_key_internal(&conn, key_id)?;
        let used_events =
            Self::get_used_events_internal(&conn, key_id, &usage_month)?;

        let (
            plan_id,
            plan_limit,
            extensions_total,
            effective_limit,
            remaining_events,
        ) = if let Some((plan_id, plan_limit)) = plan_info {
            let extensions_total = Self::get_extensions_total_internal(
                &conn,
                key_id,
                &usage_month,
            )?;
            let effective_limit = plan_limit + extensions_total;
            let remaining = std::cmp::max(0, effective_limit - used_events);
            (
                Some(plan_id),
                Some(plan_limit),
                extensions_total,
                Some(effective_limit),
                Some(remaining),
            )
        } else {
            (None, None, 0, None, None)
        };

        Ok(ApiKeyQuotaStatus {
            api_key_id: key_id.to_string(),
            usage_month,
            plan_id,
            plan_limit,
            extensions_total,
            effective_limit,
            used_events,
            remaining_events,
            has_quota: plan_limit.is_some(),
        })
    }

    pub fn consume_monthly_quota(
        &self,
        key_id: &str,
    ) -> Result<ApiKeyQuotaStatus, DatabaseError> {
        let usage_month = Self::current_usage_month();
        let now = Self::now();

        let conn = self.lock_conn()?;
        let is_management = Self::is_management_key_internal(&conn, key_id)?;

        if is_management {
            return Ok(ApiKeyQuotaStatus {
                api_key_id: key_id.to_string(),
                usage_month,
                plan_id: None,
                plan_limit: None,
                extensions_total: 0,
                effective_limit: None,
                used_events: 0,
                remaining_events: None,
                has_quota: false,
            });
        }

        let plan_info = Self::get_plan_for_key_internal(&conn, key_id)?;
        let used_before =
            Self::get_used_events_internal(&conn, key_id, &usage_month)?;

        let (
            plan_id,
            plan_limit,
            extensions_total,
            effective_limit,
            remaining_after,
        ) = if let Some((plan_id, plan_limit)) = plan_info {
            let extensions_total = Self::get_extensions_total_internal(
                &conn,
                key_id,
                &usage_month,
            )?;
            let effective_limit = plan_limit + extensions_total;

            if used_before >= effective_limit {
                return Err(DatabaseError::RateLimitExceeded(format!(
                    "Monthly quota exceeded: month={} used={} limit={}",
                    usage_month, used_before, effective_limit
                )));
            }

            let remaining_after =
                std::cmp::max(0, effective_limit - (used_before + 1));
            (
                Some(plan_id),
                Some(plan_limit),
                extensions_total,
                Some(effective_limit),
                Some(remaining_after),
            )
        } else {
            (None, None, 0, None, None)
        };

        conn.execute(
            "INSERT INTO api_key_usage (api_key_id, usage_month, used_events, updated_at)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(api_key_id, usage_month)
             DO UPDATE SET used_events = api_key_usage.used_events + 1, updated_at = excluded.updated_at",
            params![key_id, usage_month, now],
        )
        .map_err(|e| DatabaseError::Update(e.to_string()))?;

        let used_after = used_before + 1;

        Ok(ApiKeyQuotaStatus {
            api_key_id: key_id.to_string(),
            usage_month,
            plan_id,
            plan_limit,
            extensions_total,
            effective_limit,
            used_events: used_after,
            remaining_events: remaining_after,
            has_quota: plan_limit.is_some(),
        })
    }
}

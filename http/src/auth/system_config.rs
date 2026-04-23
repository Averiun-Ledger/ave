use super::{
    database::DatabaseError,
    models::{
        SystemConfig, SystemConfigEndpointRateLimit, SystemConfigValue,
        SystemConfigValueType,
    },
};
use ave_bridge::auth::{AuthConfig, EndpointRateLimit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemConfigKey {
    ApiKeyDefaultTtlSeconds,
    ApiKeyMaxKeysPerUser,
    MaxLoginAttempts,
    LockoutDurationSeconds,
    RateLimitEnable,
    RateLimitWindowSeconds,
    RateLimitMaxRequests,
    RateLimitLimitByKey,
    RateLimitLimitByIp,
    RateLimitCleanupIntervalSeconds,
    RateLimitSensitiveEndpoints,
    AuditEnable,
    AuditRetentionDays,
    AuditMaxEntries,
}

impl SystemConfigKey {
    pub const ALL: [Self; 14] = [
        Self::ApiKeyDefaultTtlSeconds,
        Self::ApiKeyMaxKeysPerUser,
        Self::MaxLoginAttempts,
        Self::LockoutDurationSeconds,
        Self::RateLimitEnable,
        Self::RateLimitWindowSeconds,
        Self::RateLimitMaxRequests,
        Self::RateLimitLimitByKey,
        Self::RateLimitLimitByIp,
        Self::RateLimitCleanupIntervalSeconds,
        Self::RateLimitSensitiveEndpoints,
        Self::AuditEnable,
        Self::AuditRetentionDays,
        Self::AuditMaxEntries,
    ];

    pub fn parse(key: &str) -> Result<Self, DatabaseError> {
        match key {
            "api_key_default_ttl_seconds" => Ok(Self::ApiKeyDefaultTtlSeconds),
            "api_key_max_keys_per_user" => Ok(Self::ApiKeyMaxKeysPerUser),
            "max_login_attempts" => Ok(Self::MaxLoginAttempts),
            "lockout_duration_seconds" => Ok(Self::LockoutDurationSeconds),
            "rate_limit_enable" => Ok(Self::RateLimitEnable),
            "rate_limit_window_seconds" => Ok(Self::RateLimitWindowSeconds),
            "rate_limit_max_requests" => Ok(Self::RateLimitMaxRequests),
            "rate_limit_limit_by_key" => Ok(Self::RateLimitLimitByKey),
            "rate_limit_limit_by_ip" => Ok(Self::RateLimitLimitByIp),
            "rate_limit_cleanup_interval_seconds" => {
                Ok(Self::RateLimitCleanupIntervalSeconds)
            }
            "rate_limit_sensitive_endpoints" => {
                Ok(Self::RateLimitSensitiveEndpoints)
            }
            "audit_enable" => Ok(Self::AuditEnable),
            "audit_retention_days" => Ok(Self::AuditRetentionDays),
            "audit_max_entries" => Ok(Self::AuditMaxEntries),
            _ => Err(DatabaseError::NotFound(format!(
                "System config key '{}' not found",
                key
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKeyDefaultTtlSeconds => "api_key_default_ttl_seconds",
            Self::ApiKeyMaxKeysPerUser => "api_key_max_keys_per_user",
            Self::MaxLoginAttempts => "max_login_attempts",
            Self::LockoutDurationSeconds => "lockout_duration_seconds",
            Self::RateLimitEnable => "rate_limit_enable",
            Self::RateLimitWindowSeconds => "rate_limit_window_seconds",
            Self::RateLimitMaxRequests => "rate_limit_max_requests",
            Self::RateLimitLimitByKey => "rate_limit_limit_by_key",
            Self::RateLimitLimitByIp => "rate_limit_limit_by_ip",
            Self::RateLimitCleanupIntervalSeconds => {
                "rate_limit_cleanup_interval_seconds"
            }
            Self::RateLimitSensitiveEndpoints => {
                "rate_limit_sensitive_endpoints"
            }
            Self::AuditEnable => "audit_enable",
            Self::AuditRetentionDays => "audit_retention_days",
            Self::AuditMaxEntries => "audit_max_entries",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::ApiKeyDefaultTtlSeconds => "Default API key TTL in seconds",
            Self::ApiKeyMaxKeysPerUser => {
                "Maximum number of service API keys per user (0 = unlimited)"
            }
            Self::MaxLoginAttempts => {
                "Maximum failed login attempts before account lockout"
            }
            Self::LockoutDurationSeconds => {
                "Account lockout duration in seconds"
            }
            Self::RateLimitEnable => "Enable rate limiting",
            Self::RateLimitWindowSeconds => "Rate limit time window in seconds",
            Self::RateLimitMaxRequests => "Maximum requests per window",
            Self::RateLimitLimitByKey => "Enable rate limiting by API key",
            Self::RateLimitLimitByIp => "Enable rate limiting by IP address",
            Self::RateLimitCleanupIntervalSeconds => {
                "Delete stale rate limit rows older than this interval"
            }
            Self::RateLimitSensitiveEndpoints => {
                "JSON array of endpoint-specific rate limit overrides"
            }
            Self::AuditEnable => "Enable audit logging",
            Self::AuditRetentionDays => {
                "Audit log retention in days (0 = keep forever)"
            }
            Self::AuditMaxEntries => {
                "Maximum audit log entries to retain (0 = unlimited)"
            }
        }
    }

    pub const fn value_type(self) -> SystemConfigValueType {
        match self {
            Self::RateLimitEnable
            | Self::RateLimitLimitByKey
            | Self::RateLimitLimitByIp
            | Self::AuditEnable => SystemConfigValueType::Boolean,
            Self::RateLimitSensitiveEndpoints => {
                SystemConfigValueType::EndpointRateLimits
            }
            _ => SystemConfigValueType::Integer,
        }
    }

    pub fn startup_value(
        self,
        config: &AuthConfig,
    ) -> Result<SystemConfigValue, DatabaseError> {
        Ok(match self {
            Self::ApiKeyDefaultTtlSeconds => {
                SystemConfigValue::Integer(config.api_key.default_ttl_seconds)
            }
            Self::ApiKeyMaxKeysPerUser => SystemConfigValue::Integer(
                config.api_key.max_keys_per_user as i64,
            ),
            Self::MaxLoginAttempts => {
                SystemConfigValue::Integer(config.lockout.max_attempts as i64)
            }
            Self::LockoutDurationSeconds => {
                SystemConfigValue::Integer(config.lockout.duration_seconds)
            }
            Self::RateLimitEnable => {
                SystemConfigValue::Boolean(config.rate_limit.enable)
            }
            Self::RateLimitWindowSeconds => {
                SystemConfigValue::Integer(config.rate_limit.window_seconds)
            }
            Self::RateLimitMaxRequests => SystemConfigValue::Integer(
                config.rate_limit.max_requests as i64,
            ),
            Self::RateLimitLimitByKey => {
                SystemConfigValue::Boolean(config.rate_limit.limit_by_key)
            }
            Self::RateLimitLimitByIp => {
                SystemConfigValue::Boolean(config.rate_limit.limit_by_ip)
            }
            Self::RateLimitCleanupIntervalSeconds => {
                SystemConfigValue::Integer(
                    config.rate_limit.cleanup_interval_seconds,
                )
            }
            Self::RateLimitSensitiveEndpoints => {
                SystemConfigValue::EndpointRateLimits(
                    config
                        .rate_limit
                        .sensitive_endpoints
                        .clone()
                        .into_iter()
                        .map(SystemConfigEndpointRateLimit::from)
                        .collect(),
                )
            }
            Self::AuditEnable => {
                SystemConfigValue::Boolean(config.session.audit_enable)
            }
            Self::AuditRetentionDays => SystemConfigValue::Integer(
                config.session.audit_retention_days as i64,
            ),
            Self::AuditMaxEntries => SystemConfigValue::Integer(
                config.session.audit_max_entries as i64,
            ),
        })
    }

    pub fn parse_persisted_value(
        self,
        raw: &str,
    ) -> Result<SystemConfigValue, DatabaseError> {
        match self {
            Self::RateLimitEnable
            | Self::RateLimitLimitByKey
            | Self::RateLimitLimitByIp
            | Self::AuditEnable => {
                parse_bool(self.as_str(), raw).map(SystemConfigValue::Boolean)
            }
            Self::RateLimitSensitiveEndpoints => {
                let endpoints: Vec<EndpointRateLimit> =
                    serde_json::from_str(raw).map_err(|e| {
                        DatabaseError::Validation(format!(
                            "{} must be valid JSON: {}",
                            self.as_str(),
                            e
                        ))
                    })?;
                Ok(SystemConfigValue::EndpointRateLimits(
                    endpoints
                        .into_iter()
                        .map(SystemConfigEndpointRateLimit::from)
                        .collect(),
                ))
            }
            _ => raw.parse::<i64>().map(SystemConfigValue::Integer).map_err(
                |_| {
                    DatabaseError::Validation(format!(
                        "{} must be a valid integer",
                        self.as_str()
                    ))
                },
            ),
        }
    }

    pub fn serialize_value(
        self,
        value: &SystemConfigValue,
    ) -> Result<String, DatabaseError> {
        self.validate_value(value)?;

        match (self, value) {
            (
                Self::RateLimitEnable
                | Self::RateLimitLimitByKey
                | Self::RateLimitLimitByIp
                | Self::AuditEnable,
                SystemConfigValue::Boolean(value),
            ) => Ok(value.to_string()),
            (
                Self::RateLimitSensitiveEndpoints,
                SystemConfigValue::EndpointRateLimits(value),
            ) => {
                let endpoints: Vec<EndpointRateLimit> = value
                    .iter()
                    .cloned()
                    .map(EndpointRateLimit::from)
                    .collect();
                serde_json::to_string(&endpoints)
                    .map_err(|e| DatabaseError::Validation(e.to_string()))
            }
            (_, SystemConfigValue::Integer(value)) => Ok(value.to_string()),
            _ => Err(DatabaseError::Validation(format!(
                "{} expects a {} value",
                self.as_str(),
                self.value_type_name(),
            ))),
        }
    }

    pub fn validate_value(
        self,
        value: &SystemConfigValue,
    ) -> Result<(), DatabaseError> {
        match (self, value) {
            (
                Self::ApiKeyDefaultTtlSeconds,
                SystemConfigValue::Integer(ttl_value),
            ) => {
                if *ttl_value < 0 {
                    return Err(DatabaseError::Validation(
                        "api_key_default_ttl_seconds must be >= 0 (0 = no expiration)".to_string(),
                    ));
                }
            }
            (Self::ApiKeyMaxKeysPerUser, SystemConfigValue::Integer(value)) => {
                if *value < 0 || *value > u32::MAX as i64 {
                    return Err(DatabaseError::Validation(
                        "api_key_max_keys_per_user must be a valid non-negative integer".to_string(),
                    ));
                }
            }
            (Self::MaxLoginAttempts, SystemConfigValue::Integer(value))
            | (Self::RateLimitMaxRequests, SystemConfigValue::Integer(value)) => {
                if *value <= 0 || *value > u32::MAX as i64 {
                    return Err(DatabaseError::Validation(format!(
                        "{} must be > 0",
                        self.as_str()
                    )));
                }
            }
            (
                Self::LockoutDurationSeconds
                | Self::RateLimitWindowSeconds
                | Self::RateLimitCleanupIntervalSeconds,
                SystemConfigValue::Integer(value),
            ) => {
                if *value <= 0 {
                    return Err(DatabaseError::Validation(format!(
                        "{} must be > 0",
                        self.as_str()
                    )));
                }
            }
            (
                Self::AuditRetentionDays | Self::AuditMaxEntries,
                SystemConfigValue::Integer(value),
            ) => {
                if *value < 0 || *value > u32::MAX as i64 {
                    return Err(DatabaseError::Validation(format!(
                        "{} must be a valid non-negative integer",
                        self.as_str()
                    )));
                }
            }
            (
                Self::RateLimitEnable
                | Self::RateLimitLimitByKey
                | Self::RateLimitLimitByIp
                | Self::AuditEnable,
                SystemConfigValue::Boolean(_),
            ) => {}
            (
                Self::RateLimitSensitiveEndpoints,
                SystemConfigValue::EndpointRateLimits(endpoints),
            ) => {
                for endpoint in endpoints {
                    if endpoint.endpoint.trim().is_empty() {
                        return Err(DatabaseError::Validation(
                            "rate_limit_sensitive_endpoints entries must have a non-empty endpoint".to_string(),
                        ));
                    }
                    if endpoint.max_requests == 0 {
                        return Err(DatabaseError::Validation(
                            "rate_limit_sensitive_endpoints max_requests must be > 0".to_string(),
                        ));
                    }
                    if let Some(window) = endpoint.window_seconds
                        && window <= 0
                    {
                        return Err(DatabaseError::Validation(
                            "rate_limit_sensitive_endpoints window_seconds must be > 0".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(DatabaseError::Validation(format!(
                    "{} expects a {} value",
                    self.as_str(),
                    self.value_type_name(),
                )));
            }
        }

        Ok(())
    }

    const fn value_type_name(self) -> &'static str {
        match self.value_type() {
            SystemConfigValueType::Integer => "integer",
            SystemConfigValueType::Boolean => "boolean",
            SystemConfigValueType::EndpointRateLimits => "endpoint_rate_limits",
        }
    }
}

pub fn system_config_from_row(
    key: &str,
    value: &str,
    description: Option<String>,
    updated_at: i64,
    updated_by: Option<i64>,
    updated_by_username: Option<String>,
) -> Result<SystemConfig, DatabaseError> {
    let key_id = SystemConfigKey::parse(key)?;
    let typed_value = key_id.parse_persisted_value(value)?;

    Ok(SystemConfig {
        key: key.to_string(),
        value_type: key_id.value_type(),
        value: typed_value,
        description,
        updated_at,
        updated_by,
        updated_by_username,
    })
}

fn parse_bool(key: &str, value: &str) -> Result<bool, DatabaseError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(DatabaseError::Validation(format!(
            "{} must be a boolean (true/false or 1/0)",
            key
        ))),
    }
}

use super::database::{AuthDatabase, DatabaseError};
use super::models::{ErrorResponse, PaginationQuery};
use axum::{Json, http::StatusCode};
use std::sync::Arc;
use std::time::Instant;
use tracing::error;

const TARGET: &str = "ave::http::auth";

pub type HttpErrorResponse = (StatusCode, Json<ErrorResponse>);

#[derive(Clone, Copy)]
pub struct DatabaseErrorMapping {
    permission_denied: StatusCode,
    account_locked: StatusCode,
    password_change_required: StatusCode,
}

impl DatabaseErrorMapping {
    pub const fn admin() -> Self {
        Self {
            permission_denied: StatusCode::FORBIDDEN,
            account_locked: StatusCode::FORBIDDEN,
            password_change_required: StatusCode::FORBIDDEN,
        }
    }

    pub const fn login() -> Self {
        Self {
            permission_denied: StatusCode::UNAUTHORIZED,
            account_locked: StatusCode::UNAUTHORIZED,
            password_change_required: StatusCode::FORBIDDEN,
        }
    }
}

pub fn db_error_to_response(
    err: DatabaseError,
    mapping: DatabaseErrorMapping,
) -> HttpErrorResponse {
    let (status, message) = match err {
        DatabaseError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        DatabaseError::Duplicate(msg) => (StatusCode::CONFLICT, msg),
        DatabaseError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
        DatabaseError::PermissionDenied(msg) => {
            (mapping.permission_denied, msg)
        }
        DatabaseError::AccountLocked(msg) => (mapping.account_locked, msg),
        DatabaseError::RateLimitExceeded(msg) => {
            (StatusCode::TOO_MANY_REQUESTS, msg)
        }
        DatabaseError::PasswordChangeRequired(msg) => {
            (mapping.password_change_required, msg)
        }
        other => {
            // Never leak internal database details to clients
            error!(target: TARGET, error = %other, "unmapped database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
        }
    };

    (status, Json(ErrorResponse { error: message }))
}

/// Map a pre-auth rate limit check failure to an HTTP error response.
///
/// A genuine `RateLimitExceeded` produces 429; any other (internal) error
/// produces a generic 500 so database details are never leaked to clients.
pub fn rate_limit_error_response(err: DatabaseError) -> HttpErrorResponse {
    match err {
        DatabaseError::RateLimitExceeded(msg) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: msg }),
        ),
        other => {
            error!(target: TARGET, error = %other, "rate limit check failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal error while checking rate limit"
                        .to_string(),
                }),
            )
        }
    }
}

pub const fn request_result_from_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        200..=299 => "success",
        400 => "bad_request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        500..=599 => "internal_error",
        _ => "error",
    }
}

/// Normalizes pagination query parameters, returning explicit 400 errors for
/// invalid values instead of silently clamping.
pub fn normalize_pagination(
    query: &PaginationQuery,
    default_limit: i64,
    max_limit: i64,
) -> Result<(i64, i64), HttpErrorResponse> {
    let limit = match query.limit {
        Some(limit) if limit > 0 && limit <= max_limit => limit,
        Some(limit) if limit <= 0 => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Limit must be positive (got {})", limit),
                }),
            ));
        }
        Some(limit) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Limit must not exceed {} (got {})",
                        max_limit, limit
                    ),
                }),
            ));
        }
        None => default_limit,
    };

    let offset = match query.offset {
        Some(offset) if offset >= 0 => offset,
        Some(offset) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Offset must be non-negative (got {})",
                        offset
                    ),
                }),
            ));
        }
        None => 0,
    };

    Ok((limit, offset))
}

pub async fn run_db<T, F>(
    db: &Arc<AuthDatabase>,
    operation: &'static str,
    mapping: DatabaseErrorMapping,
    work: F,
) -> Result<T, HttpErrorResponse>
where
    T: Send + 'static,
    F: FnOnce(AuthDatabase) -> Result<T, DatabaseError> + Send + 'static,
{
    let started = Instant::now();
    match db.run_blocking(operation, work).await {
        Ok(result) => {
            db.record_request_metrics(operation, "success", started.elapsed());
            Ok(result)
        }
        Err(err) => {
            let response = db_error_to_response(err, mapping);
            db.record_request_metrics(
                operation,
                request_result_from_status(response.0),
                started.elapsed(),
            );
            Err(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_error_response_never_leaks_internal_details() {
        let (status, Json(body)) = db_error_to_response(
            DatabaseError::Query(
                "near \"SELECT\": syntax error".to_string(),
            ),
            DatabaseErrorMapping::admin(),
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
    }

    #[test]
    fn rate_limit_response_keeps_quota_message() {
        let (status, Json(body)) = rate_limit_error_response(
            DatabaseError::RateLimitExceeded(
                "Rate limit exceeded: 100 requests in 60 seconds".to_string(),
            ),
        );
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.error.contains("Rate limit exceeded"));
    }

    #[test]
    fn rate_limit_response_hides_internal_errors() {
        let (status, Json(body)) = rate_limit_error_response(
            DatabaseError::Query("database is locked".to_string()),
        );
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal error while checking rate limit");
    }
}

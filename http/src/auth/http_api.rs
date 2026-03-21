use super::database::{AuthDatabase, DatabaseError};
use super::models::ErrorResponse;
use axum::{Json, http::StatusCode};
use std::sync::Arc;
use std::time::Instant;

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
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    (status, Json(ErrorResponse { error: message }))
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

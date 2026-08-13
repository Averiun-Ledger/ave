//! Extractors that normalize axum rejections into the API's canonical
//! `ErrorResponse` body (`{"error": "…"}`).
//!
//! Every error response of the API shares the same JSON shape and a
//! standards-based status code:
//!
//! - 400: malformed JSON body, invalid path or query parameters.
//! - 413: request body larger than the configured limit.
//! - 415: `Content-Type` is not `application/json`.
//! - 422: well-formed JSON that does not match the expected schema.

use axum::{
    Json,
    extract::{
        FromRequest, FromRequestParts, Path, Query, Request,
        rejection::JsonRejection,
    },
    http::{StatusCode, request::Parts},
};
use serde::de::DeserializeOwned;

use crate::auth::models::ErrorResponse;

/// Rejection returned by the API extractors: the canonical error body.
type ApiRejection = (StatusCode, Json<ErrorResponse>);

const fn reject(status: StatusCode, message: String) -> ApiRejection {
    (status, Json(ErrorResponse { error: message }))
}

const fn json_rejection_status(rejection: &JsonRejection) -> StatusCode {
    match rejection {
        JsonRejection::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
        JsonRejection::JsonDataError(_) => StatusCode::UNPROCESSABLE_ENTITY,
        JsonRejection::MissingJsonContentType(_) => {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        }
        JsonRejection::BytesRejection(_) => StatusCode::PAYLOAD_TOO_LARGE,
        // The enum is non-exhaustive; any future rejection kind defaults to
        // a client error.
        _ => StatusCode::BAD_REQUEST,
    }
}

/// JSON body extractor that reports rejections with the canonical error body.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiRejection;

    async fn from_request(
        req: Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(reject(
                json_rejection_status(&rejection),
                rejection.body_text(),
            )),
        }
    }
}

/// Query string extractor that reports rejections with the canonical error
/// body.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => {
                Err(reject(StatusCode::BAD_REQUEST, rejection.body_text()))
            }
        }
    }
}

/// Path parameters extractor that reports rejections with the canonical
/// error body.
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => {
                Err(reject(StatusCode::BAD_REQUEST, rejection.body_text()))
            }
        }
    }
}

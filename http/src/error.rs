use ave_bridge::BridgeError;
use ave_bridge::Error as CoreError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// HTTP error type for the Axum API layer.
///
/// Wraps [`BridgeError`] and maps each variant to the appropriate
/// HTTP status code, returning a JSON body `{"error": "…"}`.
pub struct HttpError(BridgeError);

impl From<BridgeError> for HttpError {
    fn from(err: BridgeError) -> Self {
        Self(err)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = status_for_bridge_error(&self.0);
        let message = self.0.to_string();

        (status, Json(ErrorBody { error: message })).into_response()
    }
}

const fn status_for_bridge_error(err: &BridgeError) -> StatusCode {
    match err {
        // ── Input validation → 400 ──────────────────────────────
        BridgeError::InvalidSubjectId(_)
        | BridgeError::InvalidRequestId(_)
        | BridgeError::InvalidPublicKey(_)
        | BridgeError::InvalidSignature(_)
        | BridgeError::InvalidEventRequest(_) => StatusCode::BAD_REQUEST,

        // ── Key decrypt (wrong password) → 401 ─────────────────
        BridgeError::KeyDecrypt(_) => StatusCode::UNAUTHORIZED,

        // ── Key management → 500 ───────────────────────────────
        BridgeError::KeyDirectoryCreation(_)
        | BridgeError::KeyRead(_)
        | BridgeError::KeyRestore(_)
        | BridgeError::KeyGeneration(_)
        | BridgeError::KeyEncrypt(_)
        | BridgeError::KeyWrite(_) => StatusCode::INTERNAL_SERVER_ERROR,

        // ── Configuration → 500 ────────────────────────────────
        BridgeError::ConfigBuild(_) | BridgeError::ConfigDeserialize(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        // ── Sink authentication → 500 ──────────────────────────
        BridgeError::SinkAuth(_) => StatusCode::INTERNAL_SERVER_ERROR,

        // ── Core errors → delegate ─────────────────────────────
        BridgeError::Core(core) => status_for_core_error(core),
    }
}

const fn status_for_core_error(err: &CoreError) -> StatusCode {
    match err {
        // ── 400 Bad Request ────────────────────────────────────
        CoreError::InvalidSignature(_)
        | CoreError::InvalidSubjectId(_)
        | CoreError::InvalidQueryParams(_)
        | CoreError::InvalidEventRequest(_) => StatusCode::BAD_REQUEST,

        // ── 401 Unauthorized ───────────────────────────────────
        CoreError::Unauthorized(_) => StatusCode::UNAUTHORIZED,

        // ── 403 Forbidden ──────────────────────────────────────
        CoreError::Forbidden(_) => StatusCode::FORBIDDEN,

        // ── 503 Service Unavailable ───────────────────────────
        CoreError::SafeMode(_) => StatusCode::SERVICE_UNAVAILABLE,

        // ── 404 Not Found ──────────────────────────────────────
        CoreError::RequestNotFound(_)
        | CoreError::ApprovalNotFound(_)
        | CoreError::SubjectNotFound(_)
        | CoreError::GovernanceNotFound(_)
        | CoreError::WitnessesNotFound(_)
        | CoreError::NoEventsFound(_)
        | CoreError::EventNotFound { .. }
        | CoreError::NoPendingTransfers => StatusCode::NOT_FOUND,

        // ── 409 Conflict ───────────────────────────────────────
        CoreError::InvalidRequestState(_)
        | CoreError::InvalidApprovalState(_)
        | CoreError::SubjectNotActive(_) => StatusCode::CONFLICT,

        // ── 422 Unprocessable Entity ───────────────────────────
        CoreError::RequestProcessing(_)
        | CoreError::ValidationFailed(_)
        | CoreError::SchemaValidation(_) => StatusCode::UNPROCESSABLE_ENTITY,

        // ── 501 Not Implemented ────────────────────────────────
        CoreError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,

        // ── 502 Bad Gateway ────────────────────────────────────
        CoreError::Network(_) | CoreError::NetworkState(_) => {
            StatusCode::BAD_GATEWAY
        }

        // ── 504 Gateway Timeout ────────────────────────────────
        CoreError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,

        // ── 500 Internal Server Error (everything else) ────────
        CoreError::SystemInit(_)
        | CoreError::ActorCreation { .. }
        | CoreError::MissingResource { .. }
        | CoreError::SigningFailed(_)
        | CoreError::ApprovalUpdateFailed(_)
        | CoreError::AuthOperation(_)
        | CoreError::QueryFailed(_)
        | CoreError::DatabaseError(_)
        | CoreError::ActorCommunication { .. }
        | CoreError::UnexpectedResponse { .. }
        | CoreError::ActorError(_)
        | CoreError::TransferFailed(_)
        | CoreError::DistributionFailed(_)
        | CoreError::UpdateFailed(_, _)
        | CoreError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

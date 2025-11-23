use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

// Error
pub enum Error {
    Ave(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Ave(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
            }
        }
    }
}

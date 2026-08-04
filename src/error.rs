use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error(transparent)]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error")]
    Internal,
}

/// Error model for Bitwarden API compatibility
#[derive(Serialize)]
struct ErrorModel<'a> {
    message: &'a str,
    object: &'static str,
}

/// API Error response compatible with Bitwarden clients
/// This format ensures clients properly handle authentication failures
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorResponse<'a> {
    message: &'a str,
    validation_errors: std::collections::HashMap<&'static str, Vec<&'a str>>,
    error_model: ErrorModel<'a>,
    error: &'static str,
    #[serde(rename = "error_description")]
    error_description: &'static str,
    exception_message: Option<()>,
    exception_stack_trace: Option<()>,
    inner_exception_message: Option<()>,
    object: &'static str,
}

impl<'a> ApiErrorResponse<'a> {
    fn new(message: &'a str) -> Self {
        let mut validation_errors = std::collections::HashMap::with_capacity(1);
        validation_errors.insert("", vec![message]);

        Self {
            message,
            validation_errors,
            error_model: ErrorModel {
                message,
                object: "error",
            },
            error: "",
            error_description: "",
            exception_message: None,
            exception_stack_trace: None,
            inner_exception_message: None,
            object: "error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Worker(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Worker error: {}", e),
            ),
            AppError::Database => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::UnprocessableEntity(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AppError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.clone()),
            AppError::JsonWebToken(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        // Use Bitwarden-compatible error format for all error responses
        // This ensures clients properly handle authentication failures and logout when needed
        let error_response = ApiErrorResponse::new(&error_message);
        let body = Json(json!(error_response));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::ApiErrorResponse;

    #[test]
    fn api_error_uses_bitwarden_field_names() {
        let value = serde_json::to_value(ApiErrorResponse::new("too large")).unwrap();
        assert_eq!(value["message"], "too large");
        assert_eq!(value["errorModel"]["object"], "error");
        assert!(value.get("validationErrors").is_some());
        assert!(value.get("exceptionMessage").is_some());
        assert!(value.get("error_description").is_some());
        assert!(value.get("error_model").is_none());
    }
}

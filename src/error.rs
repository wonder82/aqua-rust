//! 统一错误结构：{error: {type, code, message}} 三段式（前端契约依赖）

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub error_type: String,
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, error_type: &str, code: &str, message: &str) -> Self {
        Self {
            status,
            error_type: error_type.to_string(),
            code: code.to_string(),
            message: message.to_string(),
        }
    }
    pub fn bad_request(msg: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request_error", "bad_request", msg)
    }
    pub fn unauthorized(msg: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_request_error", "unauthorized", msg)
    }
    pub fn forbidden(msg: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, "invalid_request_error", "forbidden", msg)
    }
    pub fn not_found(msg: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "invalid_request_error", "not_found", msg)
    }
    pub fn rate_limited(msg: &str) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded", "rate_limit_exceeded", msg)
    }
    pub fn service_unavailable(msg: &str) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "server_error", "service_unavailable", msg)
    }
    pub fn internal(msg: &str) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "internal_error", msg)
    }
    pub fn bad_gateway(msg: &str) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "server_error", "upstream_error", msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorBody {
            error: ErrorDetail {
                error_type: self.error_type,
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<ApiError> for Response {
    fn from(e: ApiError) -> Self {
        e.into_response()
    }
}

pub type AppResult<T> = Result<T, ApiError>;

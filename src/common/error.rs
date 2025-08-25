use actix_session::{SessionGetError, SessionInsertError};
use actix_web::{
    error::{ErrorForbidden, ErrorInternalServerError, ErrorNotFound, ErrorUnauthorized},
    HttpResponse,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Session error: {0}")]
    Session(#[from] anyhow::Error),

    #[error("Template error: {0}")]
    Template(#[from] tera::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<SessionInsertError> for AppError {
    fn from(err: SessionInsertError) -> Self {
        AppError::Session(err.into())
    }
}

impl From<SessionGetError> for AppError {
    fn from(err: SessionGetError) -> Self {
        AppError::Session(err.into())
    }
}

impl From<actix_web::Error> for AppError {
    fn from(err: actix_web::Error) -> Self {
        AppError::BadRequest(err.to_string())
    }
}

impl actix_web::error::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(err) => {
                log::error!("Database error: {:?}", err);
                ErrorInternalServerError("Database error").error_response()
            }
            AppError::Session(err) => {
                log::error!("Session error: {:?}", err);
                ErrorInternalServerError("Session error").error_response()
            }
            AppError::Template(err) => {
                log::error!("Template error: {:?}", err);
                ErrorInternalServerError("Template error").error_response()
            }
            AppError::NotFound(msg) => {
                log::info!("Not found: {}", msg);
                ErrorNotFound(msg.clone()).error_response()
            }
            AppError::Unauthorized(msg) => {
                log::warn!("Unauthorized: {}", msg);
                ErrorUnauthorized(msg.clone()).error_response()
            }
            AppError::BadRequest(msg) => {
                log::warn!("Bad request: {}", msg);
                HttpResponse::BadRequest().body(msg.clone())
            }
            AppError::Validation(msg) => {
                log::warn!("Validation error: {}", msg);
                HttpResponse::BadRequest().body(msg.clone())
            }
            AppError::Forbidden(msg) => {
                log::warn!("Forbidden: {}", msg);
                ErrorForbidden(msg.clone()).error_response()
            }
            AppError::Internal(msg) => {
                log::error!("Internal error: {}", msg);
                ErrorInternalServerError(msg.clone()).error_response()
            }
        }
    }
}

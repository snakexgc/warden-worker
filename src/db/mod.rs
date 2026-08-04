pub mod models;

use crate::error::AppError;
use chrono::{SecondsFormat, Utc};
use worker::{D1Database, Env};

pub fn get_db(env: &Env) -> Result<D1Database, AppError> {
    env.d1("vaultsql").map_err(AppError::Worker)
}

pub fn now_rfc3339_millis() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Update the user's vault revision after a successful vault mutation.
///
/// Vaultwarden uses the user revision as the coarse-grained sync cursor. The
/// item revision and user revision intentionally receive the same timestamp so
/// clients can reliably decide whether another sync is required.
pub async fn update_user_revision(db: &D1Database, user_id: &str) -> Result<String, AppError> {
    let revision = now_rfc3339_millis();
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2")
        .bind(&[revision.clone().into(), user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(revision)
}

pub async fn get_user_revision(db: &D1Database, user_id: &str) -> Result<String, AppError> {
    db.prepare("SELECT updated_at FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("updated_at"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

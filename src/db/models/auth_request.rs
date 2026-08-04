use chrono::{Duration, Utc};
use worker::D1Database;

use super::device;
use crate::error::AppError;

pub async fn ensure_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS auth_requests (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            request_device_identifier TEXT NOT NULL,
            device_type INTEGER NOT NULL,
            request_ip TEXT NOT NULL,
            response_device_identifier TEXT,
            access_code_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            enc_key TEXT,
            master_password_hash TEXT,
            approved INTEGER,
            creation_date TEXT NOT NULL,
            response_date TEXT,
            authentication_date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_requests_user_id ON auth_requests(user_id)")
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn ensure_management_tables(db: &D1Database) -> Result<(), AppError> {
    device::ensure_table(db).await?;
    ensure_table(db).await
}

pub async fn purge_expired(db: &D1Database) -> Result<(), AppError> {
    let cutoff =
        (Utc::now() - Duration::minutes(15)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    db.prepare("DELETE FROM auth_requests WHERE creation_date < ?1")
        .bind(&[cutoff.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

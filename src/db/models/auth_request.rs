use chrono::{Duration, Utc};
use worker::D1Database;

use crate::error::AppError;

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

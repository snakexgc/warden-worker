use crate::error::AppError;
use worker::D1Database;

pub async fn save(
    db: &D1Database,
    user_id: &str,
    cipher_id: &str,
    archived_at: &str,
) -> Result<(), AppError> {
    db.prepare(
        "INSERT INTO archives (user_id, cipher_id, archived_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id, cipher_id) DO UPDATE SET archived_at = excluded.archived_at",
    )
    .bind(&[user_id.into(), cipher_id.into(), archived_at.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn delete(db: &D1Database, user_id: &str, cipher_id: &str) -> Result<(), AppError> {
    db.prepare("DELETE FROM archives WHERE user_id = ?1 AND cipher_id = ?2")
        .bind(&[user_id.into(), cipher_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(())
}

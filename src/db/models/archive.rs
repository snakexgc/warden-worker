use crate::error::AppError;
use worker::D1Database;

pub async fn ensure_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS archives (
            user_id TEXT NOT NULL,
            cipher_id TEXT NOT NULL,
            archived_at TEXT NOT NULL,
            PRIMARY KEY (user_id, cipher_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    db.prepare("CREATE INDEX IF NOT EXISTS idx_archives_user_id ON archives(user_id)")
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    db.prepare("CREATE INDEX IF NOT EXISTS idx_archives_cipher_id ON archives(cipher_id)")
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn save(
    db: &D1Database,
    user_id: &str,
    cipher_id: &str,
    archived_at: &str,
) -> Result<(), AppError> {
    ensure_table(db).await?;

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
    ensure_table(db).await?;

    db.prepare("DELETE FROM archives WHERE user_id = ?1 AND cipher_id = ?2")
        .bind(&[user_id.into(), cipher_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(())
}

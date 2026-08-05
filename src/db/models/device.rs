use worker::D1Database;

use crate::error::AppError;

pub async fn ensure_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_identifier TEXT NOT NULL,
            device_name TEXT,
            device_type INTEGER,
            remember_token_hash TEXT,
            push_token TEXT,
            push_uuid TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, device_identifier),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN remember_token_hash TEXT")
        .run()
        .await;
    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN push_token TEXT")
        .run()
        .await;
    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN push_uuid TEXT")
        .run()
        .await;
    Ok(())
}

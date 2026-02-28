use axum::{extract::{Query, State}, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{db, error::AppError, router::AppState};

const D1_MAX_BYTES: i64 = 500 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageQuery {
    user_id: Option<String>,
}

async fn sum_i64(db: &worker::D1Database, sql: &str, binds: &[worker::wasm_bindgen::JsValue]) -> Result<i64, AppError> {
    let bytes: Option<i64> = db
        .prepare(sql)
        .bind(binds)?
        .first(Some("bytes"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(bytes.unwrap_or(0))
}

#[worker::send]
pub async fn d1_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let user_id = q.user_id.as_deref();

    let (ciphers_bytes, sends_text_bytes, sends_file_meta_bytes) = match user_id {
        None => {
            let ciphers_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM ciphers",
                &[],
            )
            .await?;
            let sends_text_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 0",
                &[],
            )
            .await?;
            let sends_file_meta_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 1",
                &[],
            )
            .await?;
            (ciphers_bytes, sends_text_bytes, sends_file_meta_bytes)
        }
        Some(user_id) => {
            let ciphers_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM ciphers WHERE user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            let sends_text_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 0 AND user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            let sends_file_meta_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(data)), 0) AS bytes FROM sends WHERE type = 1 AND user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            (ciphers_bytes, sends_text_bytes, sends_file_meta_bytes)
        }
    };

    let send_files_bytes = 0_i64;

    let (folders_bytes, devices_bytes, totp_bytes, users_bytes) = match user_id {
        None => {
            let folders_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(name)), 0) AS bytes FROM folders",
                &[],
            )
            .await?;
            let devices_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(device_identifier) + LENGTH(COALESCE(device_name, '')) + LENGTH(COALESCE(remember_token_hash, ''))), 0) AS bytes FROM devices",
                &[],
            )
            .await?;
            let totp_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(secret_enc)), 0) AS bytes FROM two_factor_authenticator",
                &[],
            )
            .await?;
            let users_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(email) + LENGTH(COALESCE(name, '')) + LENGTH(master_password_hash) + LENGTH(COALESCE(master_password_hint, '')) + LENGTH(key) + LENGTH(private_key) + LENGTH(public_key)), 0) AS bytes FROM users",
                &[],
            )
            .await?;
            (folders_bytes, devices_bytes, totp_bytes, users_bytes)
        }
        Some(user_id) => {
            let folders_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(name)), 0) AS bytes FROM folders WHERE user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            let devices_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(device_identifier) + LENGTH(COALESCE(device_name, '')) + LENGTH(COALESCE(remember_token_hash, ''))), 0) AS bytes FROM devices WHERE user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            let totp_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(secret_enc)), 0) AS bytes FROM two_factor_authenticator WHERE user_id = ?1",
                &[user_id.into()],
            )
            .await?;
            let users_bytes = sum_i64(
                &db,
                "SELECT COALESCE(SUM(LENGTH(email) + LENGTH(COALESCE(name, '')) + LENGTH(master_password_hash) + LENGTH(COALESCE(master_password_hint, '')) + LENGTH(key) + LENGTH(private_key) + LENGTH(public_key)), 0) AS bytes FROM users WHERE id = ?1",
                &[user_id.into()],
            )
            .await?;
            (folders_bytes, devices_bytes, totp_bytes, users_bytes)
        }
    };

    let mut items = vec![
        json!({"key":"ciphers","name":"密码库（ciphers.data）","bytes":ciphers_bytes}),
        json!({"key":"sends_text","name":"Send 文本（sends.data, type=0）","bytes":sends_text_bytes}),
        json!({"key":"sends_file_meta","name":"Send 文件元数据（sends.data, type=1）","bytes":sends_file_meta_bytes}),
        json!({"key":"folders","name":"文件夹（folders.name）","bytes":folders_bytes}),
        json!({"key":"two_factor","name":"二次验证（two_factor_authenticator.secret_enc）","bytes":totp_bytes}),
        json!({"key":"devices","name":"设备（devices.*）","bytes":devices_bytes}),
        json!({"key":"users","name":"用户信息/密钥（users.*）","bytes":users_bytes}),
    ];
    items.sort_by(|a, b| {
        let a = a.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let b = b.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        b.cmp(&a)
    });

    let total_bytes: i64 = items
        .iter()
        .map(|v| v.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0))
        .sum();
    let total_percent = if D1_MAX_BYTES <= 0 {
        0.0
    } else {
        (total_bytes as f64) * 100.0 / (D1_MAX_BYTES as f64)
    };
    let remaining_bytes = (D1_MAX_BYTES - total_bytes).max(0);
    let remaining_percent = if D1_MAX_BYTES <= 0 {
        0.0
    } else {
        (remaining_bytes as f64) * 100.0 / (D1_MAX_BYTES as f64)
    };

    Ok(Json(json!({
        "object": "d1-usage",
        "maxBytes": D1_MAX_BYTES,
        "totalBytes": total_bytes,
        "totalPercent": total_percent,
        "remainingBytes": remaining_bytes,
        "remainingPercent": remaining_percent,
        "sendFilesBytes": send_files_bytes,
        "items": items,
        "userId": user_id
    })))
}

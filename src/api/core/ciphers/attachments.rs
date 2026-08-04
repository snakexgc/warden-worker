use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

use crate::{
    api::AppState,
    api::notifications::{self, UpdateType},
    auth::Claims,
    db,
    db::models::{Attachment, cipher::Cipher},
    error::AppError,
    worker_runtime::r2_file,
};

const BUCKET_BINDING: &str = "SEND_FILES_BUCKET";
const ATTACHMENT_URL_TTL_MINUTES: i64 = 5;
const ATTACHMENT_SIZE_LEEWAY: i64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRequestData {
    key: String,
    file_name: String,
    file_size: NumberOrString,
    admin_request: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn into_i64(self) -> Result<i64, AppError> {
        match self {
            Self::Number(value) => Ok(value),
            Self::String(value) => value
                .trim()
                .parse()
                .map_err(|_| AppError::BadRequest("Invalid attachment size".to_string())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentDownloadClaims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    token: String,
}

fn display_size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1} KB");
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{mb:.1} MB");
    }
    format!("{:.1} GB", mb / 1024.0)
}

fn generate_download_token(
    state: &Arc<AppState>,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<String, AppError> {
    let exp =
        (Utc::now() + chrono::Duration::minutes(ATTACHMENT_URL_TTL_MINUTES)).timestamp() as usize;
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &AttachmentDownloadClaims {
            sub: format!("{cipher_id}/{attachment_id}"),
            exp,
        },
        &jsonwebtoken::EncodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
    )?)
}

fn attachment_to_json(state: &Arc<AppState>, attachment: &Attachment) -> Result<Value, AppError> {
    let token = generate_download_token(state, &attachment.cipher_id, &attachment.id)?;
    Ok(json!({
        "id": attachment.id,
        "url": state.public_url(&format!(
            "/attachments/{}/{}?token={token}",
            attachment.cipher_id, attachment.id
        )),
        "fileName": attachment.file_name,
        "size": attachment.size.to_string(),
        "sizeName": display_size(attachment.size),
        "key": attachment.key,
        "object": "attachment"
    }))
}

async fn get_attachment(
    db: &worker::D1Database,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
) -> Result<Attachment, AppError> {
    db.prepare("SELECT * FROM cipher_attachments WHERE id = ?1 AND cipher_id = ?2 AND user_id = ?3")
        .bind(&[attachment_id.into(), cipher_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Attachment doesn't exist".to_string()))
}

pub(crate) async fn enrich_ciphers(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    ciphers: &mut [Cipher],
) -> Result<(), AppError> {
    let Some(user_id) = ciphers.iter().find_map(|cipher| cipher.user_id.as_deref()) else {
        return Ok(());
    };
    let rows: Vec<Attachment> = db
        .prepare("SELECT * FROM cipher_attachments WHERE user_id = ?1 ORDER BY created_at")
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;

    let mut grouped: HashMap<String, Vec<Value>> = HashMap::new();
    for row in rows {
        grouped
            .entry(row.cipher_id.clone())
            .or_default()
            .push(attachment_to_json(state, &row)?);
    }
    for cipher in ciphers {
        cipher.attachments = grouped.remove(&cipher.id).map(Value::Array);
    }
    Ok(())
}

pub(crate) async fn enrich_cipher(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    cipher: &mut Cipher,
) -> Result<(), AppError> {
    enrich_ciphers(db, state, std::slice::from_mut(cipher)).await
}

async fn finish_attachment_mutation(
    db: &worker::D1Database,
    state: &Arc<AppState>,
    claims: &Claims,
    cipher_id: &str,
    _revision: &str,
) -> Result<(), AppError> {
    let revision = db::update_user_revision(db, &claims.sub).await?;
    notifications::publish_cipher_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncCipherUpdate,
        claims.sub.clone(),
        cipher_id.to_string(),
        revision,
        claims.device.clone(),
    );
    Ok(())
}

#[worker::send]
pub async fn create_attachment_v2(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(cipher_id): Path<String>,
    Json(payload): Json<AttachmentRequestData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let cipher_db = super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub).await?;

    let file_size = payload.file_size.into_i64()?;
    r2_file::validate_declared_size(file_size, "Attachment")?;
    let file_name = payload.file_name;
    let attachment_id = Uuid::new_v4().to_string();
    let now = db::now_rfc3339_millis();
    let object_key = format!("attachments/{}/{}/{}", claims.sub, cipher_id, attachment_id);

    db.prepare(
        "INSERT INTO cipher_attachments (id, cipher_id, user_id, file_name, size, key, r2_object_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&[
        attachment_id.clone().into(),
        cipher_id.clone().into(),
        claims.sub.clone().into(),
        file_name.into(),
        (file_size as f64).into(),
        payload.key.into(),
        object_key.into(),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let mut cipher: Cipher = cipher_db.into();
    enrich_cipher(&db, &state, &mut cipher).await?;
    let response_key = if payload.admin_request.unwrap_or(false) {
        "cipherMiniResponse"
    } else {
        "cipherResponse"
    };
    let mut response = serde_json::Map::new();
    response.insert("object".to_string(), json!("attachment-fileUpload"));
    response.insert("attachmentId".to_string(), json!(attachment_id));
    response.insert(
        "url".to_string(),
        json!(format!("/ciphers/{cipher_id}/attachment/{attachment_id}")),
    );
    response.insert("fileUploadType".to_string(), json!(0));
    response.insert(
        response_key.to_string(),
        serde_json::to_value(cipher).map_err(|_| AppError::Internal)?,
    );
    Ok(Json(Value::Object(response)))
}

#[worker::send]
pub async fn create_attachment_legacy(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(cipher_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub).await?;

    let attachment_id = Uuid::new_v4().to_string();
    let object_key = format!("attachments/{}/{}/{}", claims.sub, cipher_id, attachment_id);
    let bucket = state
        .env
        .bucket(BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    let parsed = async {
        let mut encrypted_file_name = None;
        let mut attachment_key = None;
        let mut uploaded_size = None;
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|_| AppError::BadRequest("Invalid multipart".to_string()))?
        {
            match field.name() {
                Some("key") => {
                    attachment_key =
                        Some(field.text().await.map_err(|_| {
                            AppError::BadRequest("Invalid attachment key".to_string())
                        })?);
                }
                Some("data") => {
                    if uploaded_size.is_some() {
                        return Err(AppError::BadRequest(
                            "Multiple file data fields are not supported".to_string(),
                        ));
                    }
                    encrypted_file_name = field.file_name().map(str::to_string);
                    uploaded_size =
                        Some(r2_file::upload_field(&bucket, &object_key, &mut field).await?);
                }
                _ => {}
            }
        }
        let encrypted_file_name = encrypted_file_name
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::BadRequest("No filename provided".to_string()))?;
        let attachment_key = attachment_key
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::BadRequest("No attachment key provided".to_string()))?;
        let actual_size =
            uploaded_size.ok_or_else(|| AppError::BadRequest("Missing file data".to_string()))?;
        Ok::<_, AppError>((encrypted_file_name, attachment_key, actual_size as i64))
    }
    .await;
    let (encrypted_file_name, attachment_key, actual_size) = match parsed {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = bucket.delete(object_key.clone()).await;
            return Err(err);
        }
    };

    let now = db::now_rfc3339_millis();
    let insert_result: Result<(), AppError> = async {
        db.prepare(
            "INSERT INTO cipher_attachments (id, cipher_id, user_id, file_name, size, key, r2_object_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&[
            attachment_id.into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
            encrypted_file_name.into(),
            (actual_size as f64).into(),
            attachment_key.into(),
            object_key.clone().into(),
            now.clone().into(),
            now.clone().into(),
        ])?
        .run()
        .await
        .map_err(|err| {
            log::error!("failed to insert attachment metadata: {err}");
            AppError::Database
        })?;
        Ok(())
    }
    .await;
    if let Err(err) = insert_result {
        log::error!("attachment metadata transaction failed: {err}");
        let _ = bucket.delete(object_key).await;
        return Err(err);
    }
    db.prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3")
        .bind(&[
            now.clone().into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    finish_attachment_mutation(&db, &state, &claims, &cipher_id, &now).await?;

    let mut cipher: Cipher = super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub)
        .await?
        .into();
    enrich_cipher(&db, &state, &mut cipher).await?;
    Ok(Json(
        serde_json::to_value(cipher).map_err(|_| AppError::Internal)?,
    ))
}

#[worker::send]
pub async fn upload_attachment_v2(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub).await?;
    let attachment = get_attachment(&db, &cipher_id, &attachment_id, &claims.sub).await?;
    r2_file::validate_declared_size(attachment.size, "Attachment")?;

    let bucket = state
        .env
        .bucket(BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;

    let mut uploaded_size = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart".to_string()))?
    {
        if field.name() != Some("data") {
            continue;
        }
        uploaded_size =
            Some(r2_file::upload_field(&bucket, &attachment.r2_object_key, &mut field).await?);
        break;
    }
    let actual_size =
        uploaded_size.ok_or_else(|| AppError::BadRequest("Missing file data".to_string()))? as i64;
    let min_size = attachment
        .size
        .saturating_sub(ATTACHMENT_SIZE_LEEWAY)
        .max(0);
    let max_size = attachment.size.saturating_add(ATTACHMENT_SIZE_LEEWAY);
    if !(min_size..=max_size).contains(&actual_size) {
        let _ = bucket.delete(attachment.r2_object_key).await;
        db.prepare("DELETE FROM cipher_attachments WHERE id = ?1 AND user_id = ?2")
            .bind(&[attachment_id.into(), claims.sub.clone().into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        return Err(AppError::BadRequest(format!(
            "Attachment size mismatch (expected within [{min_size}, {max_size}], got {actual_size})"
        )));
    }

    let now = db::now_rfc3339_millis();
    let update_result: Result<(), AppError> = async {
        db.prepare("UPDATE cipher_attachments SET size = ?1, updated_at = ?2 WHERE id = ?3 AND cipher_id = ?4 AND user_id = ?5")
            .bind(&[
                (actual_size as f64).into(),
                now.clone().into(),
                attachment.id.clone().into(),
                cipher_id.clone().into(),
                claims.sub.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
    .await;
    if update_result.is_err() {
        let _ = bucket.delete(attachment.r2_object_key).await;
        return Err(AppError::Database);
    }
    db.prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3")
        .bind(&[
            now.clone().into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    finish_attachment_mutation(&db, &state, &claims, &cipher_id, &now).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn attachment_metadata(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub).await?;
    let attachment = get_attachment(&db, &cipher_id, &attachment_id, &claims.sub).await?;
    Ok(Json(attachment_to_json(&state, &attachment)?))
}

#[worker::send]
pub async fn delete_attachment(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub).await?;
    let attachment = get_attachment(&db, &cipher_id, &attachment_id, &claims.sub).await?;
    let bucket = state
        .env
        .bucket(BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    bucket
        .delete(attachment.r2_object_key)
        .await
        .map_err(|_| AppError::Internal)?;
    db.prepare("DELETE FROM cipher_attachments WHERE id = ?1 AND cipher_id = ?2 AND user_id = ?3")
        .bind(&[
            attachment_id.into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    let now = db::now_rfc3339_millis();
    db.prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3")
        .bind(&[
            now.clone().into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    finish_attachment_mutation(&db, &state, &claims, &cipher_id, &now).await?;

    let mut cipher: Cipher = super::get_cipher_dbmodel_from_db(&db, &cipher_id, &claims.sub)
        .await?
        .into();
    enrich_cipher(&db, &state, &mut cipher).await?;
    Ok(Json(json!({ "cipher": cipher })))
}

#[worker::send]
pub async fn delete_attachment_post(
    claims: Claims,
    state: State<Arc<AppState>>,
    path: Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    delete_attachment(claims, state, path).await
}

#[worker::send]
pub async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, AppError> {
    let claims = jsonwebtoken::decode::<AttachmentDownloadClaims>(
        &query.token,
        &jsonwebtoken::DecodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid attachment token".to_string()))?
    .claims;
    if claims.sub != format!("{cipher_id}/{attachment_id}") {
        return Err(AppError::Unauthorized(
            "Invalid attachment token".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    let row: Attachment = db
        .prepare("SELECT * FROM cipher_attachments WHERE id = ?1 AND cipher_id = ?2")
        .bind(&[attachment_id.into(), cipher_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Attachment doesn't exist".to_string()))?;
    let bucket = state
        .env
        .bucket(BUCKET_BINDING)
        .map_err(|_| AppError::Internal)?;
    let object = bucket
        .get(row.r2_object_key)
        .execute()
        .await
        .map_err(|_| AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Attachment doesn't exist".to_string()))?;
    let object_size = object.size();
    let body = object
        .body()
        .ok_or(AppError::Internal)?
        .response_body()
        .map_err(|_| AppError::Internal)?;
    let worker_response = worker::Response::from_body(body).map_err(|_| AppError::Internal)?;
    let mut response: Response = worker_response.into();
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", row.file_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    response.headers_mut().insert(
        r2_file::FIXED_LENGTH_HEADER,
        HeaderValue::from_str(&object_size.to_string()).map_err(|_| AppError::Internal)?,
    );
    Ok(response)
}

pub(crate) async fn delete_cipher_attachments_from_r2(
    env: &worker::Env,
    db: &worker::D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    let rows: Vec<Value> = db
        .prepare(
            "SELECT r2_object_key FROM cipher_attachments WHERE cipher_id = ?1 AND user_id = ?2",
        )
        .bind(&[cipher_id.into(), user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    if rows.is_empty() {
        return Ok(());
    }
    let bucket = env.bucket(BUCKET_BINDING).map_err(|_| AppError::Internal)?;
    for row in rows {
        let key = row
            .get("r2_object_key")
            .and_then(Value::as_str)
            .ok_or(AppError::Database)?;
        bucket
            .delete(key.to_string())
            .await
            .map_err(|_| AppError::Internal)?;
    }
    Ok(())
}

pub(crate) async fn delete_user_attachments_from_r2(
    env: &worker::Env,
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    let rows: Vec<Value> = db
        .prepare("SELECT r2_object_key FROM cipher_attachments WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    if rows.is_empty() {
        return Ok(());
    }
    let bucket = env.bucket(BUCKET_BINDING).map_err(|_| AppError::Internal)?;
    for row in rows {
        let key = row
            .get("r2_object_key")
            .and_then(Value::as_str)
            .ok_or(AppError::Database)?;
        bucket
            .delete(key.to_string())
            .await
            .map_err(|_| AppError::Internal)?;
    }
    Ok(())
}

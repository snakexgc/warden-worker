use axum::http::HeaderMap;
use axum::{Json, extract::State};
use chrono::Utc;
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;
use worker::{D1Database, query};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::logging::targets;
use crate::models::{
    archive,
    cipher::{
        Cipher, CipherDBModel, CipherData, CipherRequestData, CipherRequestFlat,
        CreateCipherRequest, client_revision_is_stale, normalize_optional_rfc3339,
    },
};
use crate::notifications::{self, UpdateType};
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;
use axum::extract::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CipherIdsRequest {
    ids: HashSet<String>,
}

#[worker::send]
pub async fn purge_personal_vault(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<super::accounts::SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::accounts::validate_password_or_otp(&db, &claims.sub, &payload).await?;

    super::attachments::delete_user_attachments_from_r2(&state.env, &db, &claims.sub).await?;
    db.prepare("DELETE FROM ciphers WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    db.prepare("DELETE FROM folders WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    let revision = db::update_user_revision(&db, &claims.sub).await?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncVault,
        claims.sub,
        revision,
        claims.device,
    );
    Ok(Json(json!({})))
}

fn now_string() -> String {
    db::now_rfc3339_millis()
}

#[derive(Debug, PartialEq)]
enum ArchiveUpdate {
    Set(String),
    Clear,
    Preserve,
}

fn archive_update_for_full_cipher(value: Option<&str>) -> ArchiveUpdate {
    match value {
        None => ArchiveUpdate::Clear,
        Some(value) => normalize_optional_rfc3339(Some(value))
            .map(ArchiveUpdate::Set)
            .unwrap_or(ArchiveUpdate::Preserve),
    }
}

async fn finish_cipher_mutation(
    db: &D1Database,
    state: &Arc<AppState>,
    user_id: &str,
    cipher_id: &str,
    _item_revision: &str,
    acting_device_id: Option<&str>,
    update_type: UpdateType,
) -> Result<(), AppError> {
    let revision = db::update_user_revision(db, user_id).await?;
    notifications::publish_cipher_update_background(
        &state.ctx,
        state.env.clone(),
        update_type,
        user_id.to_string(),
        cipher_id.to_string(),
        revision,
        acting_device_id.map(str::to_string),
    );
    Ok(())
}

async fn finish_cipher_batch_mutation(
    db: &D1Database,
    state: &Arc<AppState>,
    user_id: &str,
    acting_device_id: Option<&str>,
) -> Result<(), AppError> {
    let revision = db::update_user_revision(db, user_id).await?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncCiphers,
        user_id.to_string(),
        revision,
        acting_device_id.map(str::to_string),
    );
    Ok(())
}

async fn validate_folder(
    db: &D1Database,
    folder_id: Option<&str>,
    user_id: &str,
) -> Result<(), AppError> {
    let Some(folder_id) = folder_id else {
        return Ok(());
    };

    let folder: Option<Value> = db
        .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
        .bind(&[folder_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if folder.is_none() {
        return Err(AppError::BadRequest(
            "Folder does not exist or belongs to another user".to_string(),
        ));
    }

    Ok(())
}

pub(crate) async fn update_attachment_keys(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    attachments: Option<&Value>,
) -> Result<(), AppError> {
    let Some(attachments) = attachments else {
        return Ok(());
    };
    let attachments = attachments.as_object().ok_or_else(|| {
        AppError::BadRequest("Invalid cipher attachment key rotation data".to_string())
    })?;
    for (attachment_id, data) in attachments {
        let file_name = data
            .get("fileName")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::BadRequest("Missing attachment fileName".to_string()))?;
        let key = data
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::BadRequest("Missing attachment key".to_string()))?;
        let owner_cipher_id: Option<String> = db
            .prepare("SELECT cipher_id FROM cipher_attachments WHERE id = ?1 AND user_id = ?2")
            .bind(&[attachment_id.into(), user_id.into()])?
            .first(Some("cipher_id"))
            .await
            .map_err(|_| AppError::Database)?;
        let Some(owner_cipher_id) = owner_cipher_id else {
            log::warn!("attachment {attachment_id} no longer exists during key rotation");
            continue;
        };
        if owner_cipher_id != cipher_id {
            log::warn!("attachment {attachment_id} does not belong to cipher {cipher_id}");
            break;
        }
        db.prepare("UPDATE cipher_attachments SET file_name = ?1, key = ?2, updated_at = ?3 WHERE id = ?4 AND cipher_id = ?5 AND user_id = ?6")
            .bind(&[
                file_name.into(),
                key.into(),
                db::now_rfc3339_millis().into(),
                attachment_id.into(),
                cipher_id.into(),
                user_id.into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    }
    Ok(())
}

pub(crate) async fn get_cipher_dbmodel_from_db(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    archive::ensure_table(db).await?;

    query!(
        db,
        "SELECT ciphers.*, archives.archived_at AS archived_at
         FROM ciphers
         LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?3
         WHERE ciphers.id = ?1 AND ciphers.user_id = ?2",
        cipher_id,
        user_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))
}

async fn get_cipher_dbmodel(
    state: &Arc<AppState>,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    let db = db::get_db(&state.env)?;
    get_cipher_dbmodel_from_db(&db, cipher_id, user_id).await
}

async fn create_cipher_inner(
    claims: Claims,
    state: &Arc<AppState>,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Cipher, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user_key_id: Option<String> = if cipher_data_req.encrypted_by_key_id.is_some() {
        db.prepare("SELECT key_id FROM users WHERE id = ?1")
            .bind(&[claims.sub.clone().into()])?
            .first(Some("key_id"))
            .await
            .map_err(|_| AppError::Database)?
    } else {
        None
    };
    cipher_data_req
        .validate_encryption_context(&claims.sub, user_key_id.as_deref())
        .map_err(|message| AppError::UnprocessableEntity(message.to_string()))?;
    archive::ensure_table(&db).await?;
    cipher_data_req
        .validate_for_personal_vault(&claims.sub)
        .map_err(|message| AppError::BadRequest(message.to_string()))?;
    if !collection_ids.is_empty() {
        return Err(AppError::BadRequest(
            "Cipher collections are not supported by this personal vault".to_string(),
        ));
    }
    validate_folder(&db, cipher_data_req.folder_id.as_deref(), &claims.sub).await?;
    let now = now_string();
    let archived_at = normalize_optional_rfc3339(cipher_data_req.archived_date.as_deref());

    let cipher_data = CipherData::from_request(&cipher_data_req);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        key: cipher_data_req.key.clone(),
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        archived_at: archived_at.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipherDetails".to_string(),
        organization_use_totp: true,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids)
        },
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, key, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.key,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    if let Some(archived_at) = &archived_at {
        archive::save(&db, &claims.sub, &cipher.id, archived_at).await?;
    }

    finish_cipher_mutation(
        &db,
        state,
        &claims.sub,
        &cipher.id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherCreate,
    )
    .await?;
    super::attachments::enrich_cipher(&db, state, &mut cipher).await?;

    Ok(cipher)
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher =
        create_cipher_inner(claims, &state, payload.cipher, payload.collection_ids).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn post_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherRequestFlat>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher =
        create_cipher_inner(claims, &state, payload.cipher, payload.collection_ids).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;
    let now = now_string();

    let existing_cipher = get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;

    let cipher_data_req = payload;
    cipher_data_req
        .validate_for_personal_vault(&claims.sub)
        .map_err(|message| AppError::BadRequest(message.to_string()))?;
    if client_revision_is_stale(
        &existing_cipher.updated_at,
        cipher_data_req.last_known_revision_date.as_deref(),
    ) {
        return Err(AppError::BadRequest(
            "The client copy of this cipher is out of date. Resync the client and try again."
                .to_string(),
        ));
    }
    validate_folder(&db, cipher_data_req.folder_id.as_deref(), &claims.sub).await?;

    // A null archivedDate explicitly means "unarchive". An invalid non-null date
    // is ignored, matching Vaultwarden's existing full-update behavior.
    let archive_update = archive_update_for_full_cipher(cipher_data_req.archived_date.as_deref());
    let archived_at = match &archive_update {
        ArchiveUpdate::Set(value) => Some(value.clone()),
        ArchiveUpdate::Clear => None,
        ArchiveUpdate::Preserve => existing_cipher.archived_at.clone(),
    };

    let cipher_data = CipherData::from_request(&cipher_data_req);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        key: cipher_data_req.key.clone(),
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: existing_cipher.deleted_at,
        archived_at: archived_at.clone(),
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipherDetails".to_string(),
        organization_use_totp: true,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, key = ?4, favorite = ?5, folder_id = ?6, updated_at = ?7 WHERE id = ?8 AND user_id = ?9",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.key,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    update_attachment_keys(&db, &id, &claims.sub, cipher_data_req.attachments2.as_ref()).await?;

    match archive_update {
        ArchiveUpdate::Set(archived_at) => {
            archive::save(&db, &claims.sub, &id, &archived_at).await?;
        }
        ArchiveUpdate::Clear => archive::delete(&db, &claims.sub, &id).await?,
        ArchiveUpdate::Preserve => {
            log::warn!("Ignoring invalid archivedDate while updating cipher {id}");
        }
    }

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &cipher.id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        now,
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = Some(now.clone());
    cipher.updated_at = now;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = None;
    cipher.updated_at = now;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Restore Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

async fn archive_cipher_record(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    archived_at: String,
) -> Result<Cipher, AppError> {
    let existing = get_cipher_dbmodel_from_db(db, cipher_id, user_id).await?;

    archive::save(db, user_id, cipher_id, &archived_at).await?;
    query!(
        db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        archived_at,
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = Some(archived_at.clone());
    cipher.updated_at = archived_at;
    Ok(cipher)
}

async fn unarchive_cipher_record(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    updated_at: String,
) -> Result<Cipher, AppError> {
    let existing = get_cipher_dbmodel_from_db(db, cipher_id, user_id).await?;

    archive::delete(db, user_id, cipher_id).await?;
    query!(
        db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        updated_at,
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = None;
    cipher.updated_at = updated_at;
    Ok(cipher)
}

#[worker::send]
pub async fn archive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let mut cipher = archive_cipher_record(&db, &id, &claims.sub, now_string()).await?;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Archive Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn unarchive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let mut cipher = unarchive_cipher_record(&db, &id, &claims.sub, now_string()).await?;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Unarchive Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn archive_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let count = payload.ids.len();
    let mut ciphers = Vec::with_capacity(count);
    for id in payload.ids {
        let cipher = archive_cipher_record(&db, &id, &user_id, now_string()).await?;
        ciphers.push(cipher);
    }
    super::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    finish_cipher_batch_mutation(&db, &state, &user_id, claims.device.as_deref()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            detail: Some(format!("Action: Batch Archive ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn unarchive_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let count = payload.ids.len();
    let mut ciphers = Vec::with_capacity(count);
    for id in payload.ids {
        let cipher = unarchive_cipher_record(&db, &id, &user_id, now_string()).await?;
        ciphers.push(cipher);
    }
    super::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    finish_cipher_batch_mutation(&db, &state, &user_id, claims.device.as_deref()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            detail: Some(format!("Action: Batch Unarchive ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;
    super::attachments::delete_cipher_attachments_from_r2(&state.env, &db, &id, &claims.sub)
        .await?;
    archive::delete(&db, &claims.sub, &id).await?;

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let revision = db::now_rfc3339_millis();
    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &revision,
        claims.device.as_deref(),
        UpdateType::SyncLoginDelete,
    )
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_cipher_post(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    hard_delete_cipher(claims, State(state), headers, Path(id)).await
}

#[worker::send]
pub async fn soft_delete_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    for id in payload.ids {
        get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
            now,
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Soft Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn restore_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    let mut ciphers = Vec::with_capacity(count);
    for id in payload.ids {
        let existing = get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        let mut cipher: Cipher = existing.into();
        cipher.deleted_at = None;
        cipher.updated_at = now.clone();
        ciphers.push(cipher);
    }
    super::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Restore ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn hard_delete_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let count = payload.ids.len();
    for id in payload.ids {
        get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;
        super::attachments::delete_cipher_attachments_from_r2(&state.env, &db, &id, &claims.sub)
            .await?;
        archive::delete(&db, &claims.sub, &id).await?;
        query!(
            &db,
            "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Hard Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers_delete(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    hard_delete_ciphers(claims, State(state), headers, Json(payload)).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCipherData {
    #[serde(
        default,
        deserialize_with = "crate::models::cipher::deserialize_optional_nonempty_string"
    )]
    pub folder_id: Option<String>,
    pub ids: Vec<String>,
}

#[worker::send]
pub async fn move_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MoveCipherData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    if let Some(folder_id) = &payload.folder_id {
        let folder_exists: Option<Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if folder_exists.is_none() {
            return Err(AppError::NotFound("Folder not found".to_string()));
        }
    }

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let placeholders = payload
        .ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "UPDATE ciphers SET folder_id = ?1, updated_at = ?2 WHERE user_id = ?3 AND id IN ({})",
        placeholders
    );

    let accessible_count = if payload.ids.is_empty() {
        0
    } else {
        let count_sql = format!(
            "SELECT COUNT(*) AS count FROM ciphers WHERE user_id = ? AND id IN ({})",
            placeholders
        );
        let mut count_params = vec![claims.sub.clone().into()];
        for id in &payload.ids {
            count_params.push(id.clone().into());
        }
        db.prepare(&count_sql)
            .bind(&count_params)?
            .first::<i64>(Some("count"))
            .await
            .map_err(|_| AppError::Database)?
            .unwrap_or(0) as usize
    };

    let mut params = vec![
        payload
            .folder_id
            .clone()
            .map(|s| s.into())
            .unwrap_or_else(|| worker::wasm_bindgen::JsValue::NULL),
        now.into(),
        claims.sub.clone().into(),
    ];
    for id in &payload.ids {
        params.push(id.clone().into());
    }

    db.prepare(&sql)
        .bind(&params)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;

    if accessible_count != payload.ids.len() {
        return Err(AppError::BadRequest(format!(
            "Not all ciphers are moved! {accessible_count} of the selected {} were moved.",
            payload.ids.len()
        )));
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Move ({} items)", payload.ids.len())),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn move_ciphers_put(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MoveCipherData>,
) -> Result<Json<()>, AppError> {
    move_ciphers(claims, State(state), headers, Json(payload)).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    #[serde(
        default,
        deserialize_with = "crate::models::cipher::deserialize_optional_nonempty_string"
    )]
    pub folder_id: Option<String>,
    pub favorite: bool,
}

#[worker::send]
pub async fn get_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let cipher_rows: Vec<Value> = db
        .prepare(
            "SELECT ciphers.*, archives.archived_at AS archived_at
             FROM ciphers
             LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?2
             WHERE ciphers.user_id = ?1",
        )
        .bind(&[claims.sub.clone().into(), claims.sub.clone().into()])?
        .all()
        .await?
        .results()?;

    let mut ciphers: Vec<Cipher> = cipher_rows
        .into_iter()
        .filter_map(|row| match serde_json::from_value::<CipherDBModel>(row) {
            Ok(db_model) => Some(db_model.into()),
            Err(err) => {
                log::warn!(target: targets::DB, "Cannot parse cipher: {err:?}");
                None
            }
        })
        .collect();
    super::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let cipher: CipherDBModel = db
        .prepare(
            "SELECT ciphers.*, archives.archived_at AS archived_at
             FROM ciphers
             LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?3
             WHERE ciphers.id = ?1 AND ciphers.user_id = ?2",
        )
        .bind(&[
            id.clone().into(),
            claims.sub.clone().into(),
            claims.sub.clone().into(),
        ])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    let mut cipher: Cipher = cipher.into();
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;
    Ok(Json(cipher))
}

#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, State(state), Path(id)).await
}

#[worker::send]
pub async fn post_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    update_cipher(claims, State(state), headers, Path(id), Json(payload)).await
}

#[worker::send]
pub async fn post_cipher_partial(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    put_cipher_partial(claims, State(state), Path(id), Json(data)).await
}

#[worker::send]
pub async fn put_cipher_partial(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let now = now_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    if let Some(ref folder_id) = data.folder_id {
        let folder: Option<crate::models::folder::Folder> = db
            .prepare("SELECT * FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await?;
        if folder.is_none() {
            return Err(AppError::BadRequest(
                "Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
        data.folder_id,
        data.favorite as i32,
        now,
        id,
        claims.sub,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.folder_id = data.folder_id;
    cipher.favorite = data.favorite;
    cipher.updated_at = now;
    super::attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    finish_cipher_mutation(
        &db,
        &state,
        &claims.sub,
        &id,
        &cipher.updated_at,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;

    Ok(Json(cipher))
}

#[cfg(test)]
mod tests {
    use super::{ArchiveUpdate, CipherIdsRequest, archive_update_for_full_cipher};

    #[test]
    fn bulk_cipher_ids_are_unique_before_any_mutation() {
        let payload: CipherIdsRequest = serde_json::from_value(serde_json::json!({
            "ids": ["cipher-1", "cipher-1", "cipher-2"]
        }))
        .unwrap();
        assert_eq!(payload.ids.len(), 2);
        assert!(payload.ids.contains("cipher-1"));
        assert!(payload.ids.contains("cipher-2"));
    }

    #[test]
    fn full_cipher_update_clears_archive_for_null_and_ignores_invalid_dates() {
        assert_eq!(archive_update_for_full_cipher(None), ArchiveUpdate::Clear);
        assert_eq!(
            archive_update_for_full_cipher(Some("not-a-date")),
            ArchiveUpdate::Preserve
        );
        assert!(matches!(
            archive_update_for_full_cipher(Some("2026-09-09T12:34:56.000Z")),
            ArchiveUpdate::Set(_)
        ));
    }
}

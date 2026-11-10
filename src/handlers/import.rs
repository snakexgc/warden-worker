use axum::http::HeaderMap;
use axum::{Json, extract::State};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::folder::Folder;
use crate::models::import::ImportRequest;
use crate::models::{
    archive,
    cipher::{CipherData, normalize_optional_rfc3339},
};
use crate::notifications::{self, UpdateType};
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;

const IMPORT_BATCH_SIZE: usize = 200;

#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<ImportRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;
    // Upstream PR #7906 (`64ae55ce`): organization ids are not meaningful in
    // a personal vault; strip them so imports from organization exports pass
    // the personal-vault validation and are stored with a NULL organization.
    for cipher in &mut payload.ciphers {
        cipher.organization_id = None;
    }
    let folder_count = payload.folders.len();
    let cipher_count = payload.ciphers.len();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    for cipher in &payload.ciphers {
        cipher
            .validate_for_personal_vault(&claims.sub)
            .map_err(|message| AppError::BadRequest(message.to_string()))?;
    }
    for relationship in &payload.folder_relationships {
        if relationship.key >= payload.ciphers.len() || relationship.value >= payload.folders.len()
        {
            return Err(AppError::BadRequest(
                "Invalid cipher-folder import relationship".to_string(),
            ));
        }
    }

    let existing_folder_rows: Vec<serde_json::Value> = db
        .prepare("SELECT id FROM folders WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()?;
    let existing_folder_ids: HashSet<String> = existing_folder_rows
        .into_iter()
        .filter_map(|row| row.get("id").and_then(|id| id.as_str()).map(str::to_string))
        .collect();

    let folder_query = "INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)";

    let mut folder_stmts: Vec<D1PreparedStatement> = Vec::new();
    let mut resolved_folder_ids = Vec::with_capacity(payload.folders.len());
    for import_folder in &payload.folders {
        let (folder_id, create_folder) = match import_folder.id.as_ref() {
            Some(folder_id) if existing_folder_ids.contains(folder_id) => {
                (folder_id.clone(), false)
            }
            _ => (Uuid::new_v4().to_string(), true),
        };
        resolved_folder_ids.push(folder_id.clone());
        if !create_folder {
            continue;
        }

        let folder = Folder {
            id: folder_id,
            user_id: claims.sub.clone(),
            name: import_folder.name.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        folder_stmts.push(db.prepare(folder_query).bind(&[
            folder.id.into(),
            folder.user_id.into(),
            folder.name.into(),
            folder.created_at.into(),
            folder.updated_at.into(),
        ])?);
    }

    for relationship in &payload.folder_relationships {
        payload.ciphers[relationship.key].folder_id =
            Some(resolved_folder_ids[relationship.value].clone());
    }

    let valid_folder_ids: HashSet<&str> = existing_folder_ids
        .iter()
        .map(String::as_str)
        .chain(resolved_folder_ids.iter().map(String::as_str))
        .collect();
    if payload.ciphers.iter().any(|cipher| {
        cipher
            .folder_id
            .as_deref()
            .is_some_and(|folder_id| !valid_folder_ids.contains(folder_id))
    }) {
        return Err(AppError::BadRequest(
            "Folder does not exist or belongs to another user".to_string(),
        ));
    }

    let cipher_query = "INSERT OR IGNORE INTO ciphers (id, user_id, organization_id, type, data, key, favorite, folder_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
    let archive_query = "INSERT INTO archives (user_id, cipher_id, archived_at)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(user_id, cipher_id) DO UPDATE SET archived_at = excluded.archived_at";

    let mut cipher_stmts: Vec<D1PreparedStatement> = Vec::new();
    let mut archive_stmts: Vec<D1PreparedStatement> = Vec::new();
    for import_cipher in payload.ciphers {
        let archived_at = normalize_optional_rfc3339(import_cipher.archived_date.as_deref());
        let cipher_data = CipherData::from_request(&import_cipher);

        let id = Uuid::new_v4().to_string();
        let user_id = claims.sub.clone();
        let data = serde_json::to_string(&cipher_data).map_err(|_| AppError::Internal)?;

        cipher_stmts.push(db.prepare(cipher_query).bind(&[
            id.clone().into(),
            user_id.clone().into(),
            to_js_val(import_cipher.organization_id),
            import_cipher.r#type.into(),
            data.into(),
            to_js_val(import_cipher.key),
            import_cipher.favorite.into(),
            to_js_val(import_cipher.folder_id),
            now.clone().into(),
            now.clone().into(),
        ])?);

        if let Some(archived_at) = archived_at {
            archive_stmts.push(db.prepare(archive_query).bind(&[
                user_id.clone().into(),
                id.into(),
                archived_at.into(),
            ])?);
        }
    }
    run_batches(&db, &mut folder_stmts).await?;
    run_batches(&db, &mut cipher_stmts).await?;
    run_batches(&db, &mut archive_stmts).await?;

    let revision = db::update_user_revision(&db, &claims.sub).await?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncVault,
        claims.sub.clone(),
        revision,
        claims.device.clone(),
    );

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::Import,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("folders={folder_count}, ciphers={cipher_count}")),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

async fn run_batch(db: &D1Database, stmts: &mut Vec<D1PreparedStatement>) -> Result<(), AppError> {
    if stmts.is_empty() {
        return Ok(());
    }

    let stmts = std::mem::take(stmts);
    db.batch(stmts).await.map_err(|_| AppError::Database)?;
    Ok(())
}

async fn run_batches(
    db: &D1Database,
    stmts: &mut Vec<D1PreparedStatement>,
) -> Result<(), AppError> {
    while stmts.len() > IMPORT_BATCH_SIZE {
        let mut batch = stmts.drain(..IMPORT_BATCH_SIZE).collect();
        run_batch(db, &mut batch).await?;
    }
    run_batch(db, stmts).await
}

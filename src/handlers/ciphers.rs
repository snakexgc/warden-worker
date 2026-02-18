use axum::{extract::State, Json};
use axum::http::HeaderMap;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::cipher::{Cipher, CipherData, CipherRequestData, CreateCipherRequest, CipherRequestFlat};
use crate::notify::{self, NotifyContext, NotifyEvent};
use axum::extract::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CipherIdsRequest {
    ids: Vec<String>,
}

async fn get_cipher_dbmodel(
    env: &Arc<Env>,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    let db = db::get_db(env)?;
    query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))
}

async fn create_cipher_inner(
    claims: Claims,
    env: &Arc<Env>,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Cipher, AppError> {
    let db = db::get_db(env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids)
        },
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    Ok(cipher)
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher = create_cipher_inner(claims, &env, payload.cipher, payload.collection_ids).await?;

    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn post_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CipherRequestFlat>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher = create_cipher_inner(claims, &env, payload.cipher, payload.collection_ids).await?;

    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: existing_cipher.deleted_at,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&env, &id, &claims.sub).await?;

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

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&env, &id, &claims.sub).await?;

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

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherUpdate, // Restore is effectively an update
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Restore Cipher".to_string()),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_cipher_post(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    hard_delete_cipher(claims, State(env), headers, Path(id)).await
}

#[worker::send]
pub async fn soft_delete_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    for id in payload.ids {
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

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Soft Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(()))
}

#[worker::send]
pub async fn restore_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    for id in payload.ids {
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
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherUpdate, // Restore
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Restore ({} items)", count)),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    claims.verify_security_stamp(&db).await?;

    let count = payload.ids.len();
    for id in payload.ids {
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

    let meta = notify::extract_request_meta(&headers);
    notify::notify_best_effort(
        env.as_ref(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Hard Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers_delete(
    claims: Claims,
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    hard_delete_ciphers(claims, State(env), headers, Json(payload)).await
}

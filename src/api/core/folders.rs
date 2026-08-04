use axum::{Json, extract::State};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
use worker::query;

use crate::api::notifications::{self, UpdateType};
use crate::api::router::AppState;
use crate::auth::Claims;
use crate::db;
use crate::db::models::folder::{CreateFolderRequest, Folder, FolderResponse};
use crate::error::AppError;
use axum::extract::Path;

#[worker::send]
pub async fn create_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = db::now_rfc3339_millis();

    let folder = Folder {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        name: payload.name,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    query!(
        &db,
        "INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        folder.id,
        folder.user_id,
        folder.name,
        folder.created_at,
        folder.updated_at
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let revision = db::update_user_revision(&db, &claims.sub).await?;
    notifications::publish_folder_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncFolderCreate,
        claims.sub.clone(),
        folder.id.clone(),
        revision,
        claims.device.clone(),
    );

    let response = FolderResponse {
        id: folder.id,
        name: folder.name,
        revision_date: folder.updated_at,
        object: "folder".to_string(),
    };

    Ok(Json(response))
}

#[worker::send]
pub async fn get_folders(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    Ok(Json(json!({
        "data": folders,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let folder_db: Folder = db
        .prepare("SELECT * FROM folders WHERE id = ?1 AND user_id = ?2")
        .bind(&[id.clone().into(), claims.sub.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("Folder does not exist or belongs to another user".to_string())
        })?;

    Ok(Json(folder_db.into()))
}

#[worker::send]
pub async fn post_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    update_folder(claims, State(state), Path(id), Json(payload)).await
}

#[worker::send]
pub async fn delete_folder_post(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    delete_folder(claims, State(state), Path(id)).await
}

#[worker::send]
pub async fn delete_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let folder: Option<Folder> = db
        .prepare("SELECT * FROM folders WHERE id = ?1 AND user_id = ?2")
        .bind(&[id.clone().into(), claims.sub.clone().into()])?
        .first(None)
        .await?;

    if folder.is_none() {
        return Err(AppError::NotFound(
            "Folder does not exist or belongs to another user".to_string(),
        ));
    }

    let user_id = claims.sub.clone();
    query!(
        &db,
        "DELETE FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let revision = db::update_user_revision(&db, &claims.sub).await?;
    notifications::publish_folder_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncFolderDelete,
        claims.sub,
        id,
        revision,
        claims.device,
    );

    Ok(Json(()))
}
#[worker::send]
pub async fn update_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = db::now_rfc3339_millis();

    let existing_folder: Folder = query!(
        &db,
        "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Folder not found".to_string()))?;

    let folder = Folder {
        id: id.clone(),
        user_id: existing_folder.user_id,
        name: payload.name,
        created_at: existing_folder.created_at,
        updated_at: now.clone(),
    };

    query!(
        &db,
        "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        folder.name,
        folder.updated_at,
        folder.id,
        folder.user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let revision = db::update_user_revision(&db, &claims.sub).await?;
    notifications::publish_folder_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncFolderUpdate,
        claims.sub,
        folder.id.clone(),
        revision,
        claims.device,
    );

    let response = FolderResponse {
        id: folder.id,
        name: folder.name,
        revision_date: folder.updated_at,
        object: "folder".to_string(),
    };

    Ok(Json(response))
}

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::Utc;
use serde::Deserialize;
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
    organization::Collection,
};
use crate::notifications::{self, UpdateType};
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;

// Keep each D1 batch below the practical Workers free-plan statement envelope.
const IMPORT_BATCH_SIZE: usize = 40;
const ORGANIZATION_IMPORT_MAX_ITEMS: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationImportQuery {
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationImportRequest {
    ciphers: Vec<crate::models::cipher::CipherRequestData>,
    collections: Vec<OrganizationImportCollection>,
    #[serde(default)]
    collection_relationships: Vec<OrganizationImportRelationship>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationImportCollection {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrganizationImportRelationship {
    key: usize,
    value: usize,
}

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

#[worker::send]
pub async fn import_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrganizationImportQuery>,
    headers: HeaderMap,
    Json(mut payload): Json<OrganizationImportRequest>,
) -> Result<Json<()>, AppError> {
    if !crate::handlers::organizations::organizations_enabled(&state.env) {
        return Err(AppError::NotFound(
            "Organization support is disabled".to_string(),
        ));
    }
    if payload.ciphers.len() > ORGANIZATION_IMPORT_MAX_ITEMS
        || payload.collections.len() > ORGANIZATION_IMPORT_MAX_ITEMS
        || payload.collection_relationships.len() > ORGANIZATION_IMPORT_MAX_ITEMS * 4
    {
        return Err(AppError::BadRequest(format!(
            "An organization import supports at most {ORGANIZATION_IMPORT_MAX_ITEMS} ciphers and collections"
        )));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;
    let member =
        crate::handlers::organizations::load_membership(&db, &claims.sub, &query.organization_id)
            .await?;
    crate::handlers::organizations::require_confirmed(&member)?;

    for cipher in &payload.ciphers {
        cipher
            .validate_for_vault(&claims.sub)
            .map_err(|message| AppError::BadRequest(message.to_string()))?;
        if cipher.attachments2.is_some() {
            return Err(AppError::BadRequest(
                "Organization attachment import is not supported".to_string(),
            ));
        }
    }
    for relationship in &payload.collection_relationships {
        if relationship.key >= payload.ciphers.len()
            || relationship.value >= payload.collections.len()
        {
            return Err(AppError::BadRequest(
                "Invalid cipher-collection import relationship".to_string(),
            ));
        }
    }

    let full_access = member.has_full_access();
    let mut resolved_collection_ids = Vec::with_capacity(payload.collections.len());
    let mut collection_stmts = Vec::new();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    for import_collection in payload.collections {
        let name = crate::handlers::organizations::validate_name(
            &import_collection.name,
            "Collection name",
        )?;
        let collection_id = if let Some(collection_id) = import_collection.id {
            let collection = crate::handlers::organizations::load_collection(
                &db,
                &query.organization_id,
                &collection_id,
            )
            .await?;
            let (read_only, _, manage) = crate::handlers::organizations::collection_permissions(
                &db,
                &member,
                &collection.id,
            )
            .await?;
            if read_only && !manage {
                return Err(AppError::Forbidden(
                    "The current user cannot write to an imported collection".to_string(),
                ));
            }
            collection.id
        } else {
            if !full_access {
                return Err(AppError::Forbidden(
                    "Full organization access is required to create imported collections"
                        .to_string(),
                ));
            }
            let collection = Collection {
                id: Uuid::new_v4().to_string(),
                organization_id: query.organization_id.clone(),
                name,
                external_id: import_collection
                    .external_id
                    .filter(|value| !value.trim().is_empty()),
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            collection_stmts.push(
                db.prepare(
                    "INSERT INTO collections
                     (id, organization_id, name, external_id, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&[
                    collection.id.clone().into(),
                    collection.organization_id.into(),
                    collection.name.into(),
                    collection.external_id.into(),
                    collection.created_at.into(),
                    collection.updated_at.into(),
                ])?,
            );
            collection.id
        };
        resolved_collection_ids.push(collection_id);
    }

    let mut collections_by_cipher = vec![Vec::<String>::new(); payload.ciphers.len()];
    let mut unique_relationships = HashSet::new();
    for relationship in payload.collection_relationships {
        let pair = (relationship.key, relationship.value);
        if unique_relationships.insert(pair) {
            collections_by_cipher[relationship.key]
                .push(resolved_collection_ids[relationship.value].clone());
        }
    }
    let effective_full_access =
        crate::handlers::organizations::member_has_full_access(&db, &member).await?;
    if !effective_full_access
        && collections_by_cipher
            .iter()
            .any(|collection_ids| collection_ids.is_empty())
    {
        return Err(AppError::Forbidden(
            "Every imported cipher requires a writable collection".to_string(),
        ));
    }

    let mut cipher_stmts = Vec::new();
    let mut relation_stmts = Vec::new();
    let mut per_user_stmts = Vec::new();
    let mut cipher_ids = Vec::with_capacity(payload.ciphers.len());
    for (index, cipher) in payload.ciphers.iter_mut().enumerate() {
        cipher.organization_id = Some(query.organization_id.clone());
        cipher.folder_id = None;
        let cipher_id = Uuid::new_v4().to_string();
        let cipher_data = CipherData::from_request(cipher);
        let data = serde_json::to_string(&cipher_data).map_err(|_| AppError::Internal)?;
        cipher_stmts.push(
            db.prepare(
                "INSERT INTO ciphers
                 (id, user_id, organization_id, type, data, key, favorite, folder_id,
                  created_at, updated_at)
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?7)",
            )
            .bind(&[
                cipher_id.clone().into(),
                query.organization_id.clone().into(),
                cipher.r#type.into(),
                data.into(),
                cipher.key.clone().into(),
                now.clone().into(),
                now.clone().into(),
            ])?,
        );
        for collection_id in &collections_by_cipher[index] {
            relation_stmts.push(
                db.prepare(
                    "INSERT INTO ciphers_collections (cipher_id, collection_id) VALUES (?1, ?2)",
                )
                .bind(&[cipher_id.clone().into(), collection_id.clone().into()])?,
            );
        }
        if cipher.favorite {
            per_user_stmts.push(
                db.prepare("INSERT INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                    .bind(&[claims.sub.clone().into(), cipher_id.clone().into()])?,
            );
        }
        if let Some(archived_at) = normalize_optional_rfc3339(cipher.archived_date.as_deref()) {
            per_user_stmts.push(
                db.prepare(
                    "INSERT INTO archives (user_id, cipher_id, archived_at) VALUES (?1, ?2, ?3)",
                )
                .bind(&[
                    claims.sub.clone().into(),
                    cipher_id.clone().into(),
                    archived_at.into(),
                ])?,
            );
        }
        cipher_ids.push(cipher_id);
    }

    run_batches(&db, &mut collection_stmts).await?;
    run_batches(&db, &mut cipher_stmts).await?;
    run_batches(&db, &mut relation_stmts).await?;
    run_batches(&db, &mut per_user_stmts).await?;
    crate::handlers::ciphers::finish_organization_batch_mutation(
        &db,
        &state,
        &query.organization_id,
        &claims.sub,
        claims.device.as_deref(),
    )
    .await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::Import,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!(
                "organization={}, collections={}, ciphers={}",
                query.organization_id,
                resolved_collection_ids.len(),
                cipher_ids.len()
            )),
            meta: notify::extract_request_meta(&headers),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn organization_import_accepts_current_bitwarden_shape() {
        let payload: OrganizationImportRequest = serde_json::from_value(json!({
            "collections": [{
                "id": null,
                "name": "Shared",
                "externalId": null,
                "users": [],
                "groups": []
            }],
            "ciphers": [{
                "type": 2,
                "name": "Encrypted name",
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": "2.cipher-key",
                "secureNote": { "type": 0 }
            }],
            "collectionRelationships": [{ "key": 0, "value": 0 }]
        }))
        .expect("deserialize organization import");

        assert_eq!(payload.collections.len(), 1);
        assert_eq!(payload.ciphers.len(), 1);
        assert_eq!(payload.collection_relationships.len(), 1);
        payload.ciphers[0]
            .validate_for_vault("user-1")
            .expect("valid organization cipher");
    }
}

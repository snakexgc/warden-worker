pub(crate) mod attachments;
mod sync;

pub use super::imports::import_data;
pub use attachments::{
    attachment_metadata, create_attachment_legacy, create_attachment_v2, delete_attachment,
    delete_attachment_post, download_attachment, share_attachment, upload_attachment_v2,
};
pub use sync::sync;

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use uuid::Uuid;
use worker::{D1Database, query};

use crate::api::AppState;
use crate::api::notifications::{self, UpdateType};
use crate::auth::Claims;
use crate::db;
use crate::db::models::{
    archive,
    cipher::{
        Cipher, CipherDBModel, CipherData, CipherRequestData, CipherRequestFlat,
        CreateCipherRequest, client_revision_is_stale, normalize_optional_rfc3339,
    },
};
use crate::error::AppError;
use crate::extensions::notify::{self, NotifyContext, NotifyEvent};
use crate::worker_runtime::logging::targets;
use axum::extract::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CipherIdsRequest {
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCollectionsData {
    #[serde(alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCollectionsData {
    organization_id: String,
    cipher_ids: Vec<String>,
    collection_ids: HashSet<String>,
    remove_collections: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationIdQuery {
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSelectedCipherData {
    ciphers: Vec<CipherRequestData>,
    collection_ids: Vec<String>,
}

fn accessible_cipher_sql(single: bool) -> String {
    let id_filter = if single { "c.id = ?1 AND" } else { "" };
    let user_param = if single { "?2" } else { "?1" };
    let org_enabled_param = if single { "?3" } else { "?2" };
    format!(
        "SELECT c.id, c.user_id, c.organization_id, c.type, c.data, c.key,
                CASE WHEN c.user_id = {user_param} THEN c.favorite
                     ELSE EXISTS(SELECT 1 FROM favorites f
                                 WHERE f.user_id = {user_param} AND f.cipher_id = c.id)
                END AS favorite,
                CASE WHEN c.user_id = {user_param} THEN c.folder_id
                     ELSE (SELECT fc.folder_id FROM folders_ciphers fc
                           JOIN folders f ON f.id = fc.folder_id
                           WHERE fc.cipher_id = c.id AND f.user_id = {user_param} LIMIT 1)
                END AS folder_id,
                c.deleted_at, c.created_at, c.updated_at,
                a.archived_at AS archived_at,
                CASE WHEN c.user_id = {user_param} THEN 1
                     WHEN EXISTS(
                       SELECT 1 FROM users_organizations m
                       WHERE m.user_id = {user_param} AND m.organization_id = c.organization_id
                         AND m.status = 2 AND (
                           m.type IN (0, 1) OR m.access_all = 1 OR
                           EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                                  WHERE gu.membership_id = m.id AND g.access_all = 1) OR
                           EXISTS(SELECT 1 FROM ciphers_collections cc
                                  JOIN users_collections uc ON uc.collection_id = cc.collection_id
                                  WHERE cc.cipher_id = c.id AND uc.membership_id = m.id
                                    AND (uc.read_only = 0 OR uc.manage = 1)) OR
                           EXISTS(SELECT 1 FROM ciphers_collections cc
                                  JOIN collections_groups cg ON cg.collection_id = cc.collection_id
                                  JOIN groups_users gu ON gu.group_id = cg.group_id
                                  WHERE cc.cipher_id = c.id AND gu.membership_id = m.id
                                    AND (cg.read_only = 0 OR cg.manage = 1))
                         )
                     ) THEN 1 ELSE 0 END AS access_edit,
                CASE WHEN c.user_id = {user_param} THEN 1
                     WHEN EXISTS(
                       SELECT 1 FROM users_organizations m
                       WHERE m.user_id = {user_param} AND m.organization_id = c.organization_id
                         AND m.status = 2 AND (
                           m.type IN (0, 1) OR m.access_all = 1 OR
                           EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                                  WHERE gu.membership_id = m.id AND g.access_all = 1) OR
                           EXISTS(SELECT 1 FROM ciphers_collections cc
                                  JOIN users_collections uc ON uc.collection_id = cc.collection_id
                                  WHERE cc.cipher_id = c.id AND uc.membership_id = m.id
                                    AND uc.hide_passwords = 0) OR
                           EXISTS(SELECT 1 FROM ciphers_collections cc
                                  JOIN collections_groups cg ON cg.collection_id = cc.collection_id
                                  JOIN groups_users gu ON gu.group_id = cg.group_id
                                  WHERE cc.cipher_id = c.id AND gu.membership_id = m.id
                                    AND cg.hide_passwords = 0)
                         )
                     ) THEN 1 ELSE 0 END AS access_view_password
         FROM ciphers c
         LEFT JOIN archives a ON a.cipher_id = c.id AND a.user_id = {user_param}
         WHERE {id_filter} (
           c.user_id = {user_param} OR
           ({org_enabled_param} = 1 AND c.organization_id IS NOT NULL AND EXISTS(
             SELECT 1 FROM users_organizations m
             WHERE m.user_id = {user_param} AND m.organization_id = c.organization_id
               AND m.status = 2 AND (
                 m.type IN (0, 1) OR m.access_all = 1 OR
                 EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                        WHERE gu.membership_id = m.id AND g.access_all = 1) OR
                 EXISTS(SELECT 1 FROM ciphers_collections cc
                        JOIN users_collections uc ON uc.collection_id = cc.collection_id
                        WHERE cc.cipher_id = c.id AND uc.membership_id = m.id) OR
                 EXISTS(SELECT 1 FROM ciphers_collections cc
                        JOIN collections_groups cg ON cg.collection_id = cc.collection_id
                        JOIN groups_users gu ON gu.group_id = cg.group_id
                        WHERE cc.cipher_id = c.id AND gu.membership_id = m.id)
               )
           ))
         )"
    )
}

async fn populate_collection_ids(
    db: &D1Database,
    ciphers: &mut [Cipher],
    user_id: &str,
) -> Result<(), AppError> {
    let org_cipher_ids = ciphers
        .iter()
        .filter(|cipher| cipher.organization_id.is_some())
        .map(|cipher| cipher.id.clone())
        .collect::<Vec<_>>();
    if org_cipher_ids.is_empty() {
        return Ok(());
    }

    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for chunk in org_cipher_ids.chunks(80) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT cc.cipher_id, cc.collection_id FROM ciphers_collections cc
             JOIN ciphers c ON c.id = cc.cipher_id
             JOIN users_organizations m ON m.organization_id = c.organization_id
             WHERE cc.cipher_id IN ({placeholders}) AND m.user_id = ? AND m.status = 2
               AND (m.type IN (0, 1) OR m.access_all = 1 OR
                    EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                           WHERE gu.membership_id = m.id AND g.access_all = 1) OR
                    EXISTS(SELECT 1 FROM users_collections uc
                           WHERE uc.membership_id = m.id AND uc.collection_id = cc.collection_id) OR
                    EXISTS(SELECT 1 FROM collections_groups cg
                           JOIN groups_users gu ON gu.group_id = cg.group_id
                           WHERE gu.membership_id = m.id AND cg.collection_id = cc.collection_id))
             ORDER BY cc.collection_id"
        );
        let mut values = chunk.iter().cloned().map(Into::into).collect::<Vec<_>>();
        values.push(user_id.into());
        let rows: Vec<Value> = db
            .prepare(&sql)
            .bind(&values)?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()?;
        for row in rows {
            if let (Some(cipher_id), Some(collection_id)) = (
                row.get("cipher_id").and_then(Value::as_str),
                row.get("collection_id").and_then(Value::as_str),
            ) {
                grouped
                    .entry(cipher_id.to_string())
                    .or_default()
                    .push(collection_id.to_string());
            }
        }
    }
    for cipher in ciphers {
        if cipher.organization_id.is_some() {
            cipher.collection_ids = Some(grouped.remove(&cipher.id).unwrap_or_default());
        }
    }
    Ok(())
}

pub(crate) async fn get_accessible_ciphers(
    db: &D1Database,
    organizations_enabled: bool,
    user_id: &str,
) -> Result<Vec<Cipher>, AppError> {
    let rows: Vec<Value> = db
        .prepare(accessible_cipher_sql(false))
        .bind(&[user_id.into(), organizations_enabled.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut ciphers = rows
        .into_iter()
        .filter_map(|row| match serde_json::from_value::<CipherDBModel>(row) {
            Ok(cipher) => Some(cipher.into()),
            Err(err) => {
                log::warn!(target: targets::DB, "Cannot parse cipher: {err:?}");
                None
            }
        })
        .collect::<Vec<_>>();
    populate_collection_ids(db, &mut ciphers, user_id).await?;
    Ok(ciphers)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationPurgeQuery {
    organization: Option<String>,
}

#[worker::send]
pub async fn purge_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrganizationPurgeQuery>,
    Json(payload): Json<super::accounts::SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    super::accounts::validate_password_or_otp(&db, &claims.sub, &payload).await?;

    // 对齐 Vaultwarden purge_org_vault：携带 organization 参数时清空指定组织保险库，仅 Owner 可执行
    if let Some(org_id) = query.organization {
        if !super::organizations::organizations_enabled(&state.env) {
            return Err(AppError::NotFound(
                "Organization support is disabled".to_string(),
            ));
        }
        let member = super::organizations::load_membership(&db, &claims.sub, &org_id).await?;
        super::organizations::require_owner(&member)?;
        let rows: Vec<Value> = db
            .prepare("SELECT id FROM ciphers WHERE organization_id = ?1")
            .bind(&[org_id.clone().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()?;
        for row in rows {
            let Some(cipher_id) = row.get("id").and_then(Value::as_str) else {
                continue;
            };
            attachments::delete_cipher_attachments_from_r2(&state.env, &db, cipher_id).await?;
        }
        db.prepare("DELETE FROM ciphers WHERE organization_id = ?1")
            .bind(&[org_id.clone().into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        finish_organization_batch_mutation(
            &db,
            &state,
            &org_id,
            &claims.sub,
            claims.device.as_deref(),
        )
        .await?;
        super::events::log_event(
            &db,
            &state.env,
            1601,
            None,
            Some(&org_id),
            None,
            &claims.sub,
        )
        .await?;
        return Ok(Json(json!({})));
    }

    attachments::delete_user_attachments_from_r2(&state.env, &db, &claims.sub).await?;
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

/// 对齐 Vaultwarden `purge_trashed_ciphers`：清理软删除超过 30 天的密码项（含 R2 附件）。
pub async fn purge_trashed_ciphers(env: &worker::Env) -> Result<u64, AppError> {
    let db = db::get_db(env)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(30);
    let cutoff = cutoff
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        .to_string();
    let rows: Vec<Value> = db
        .prepare("SELECT id FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1")
        .bind(&[cutoff.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for row in &rows {
        let Some(cipher_id) = row.get("id").and_then(Value::as_str) else {
            continue;
        };
        attachments::delete_cipher_attachments_from_r2(env, &db, cipher_id).await?;
    }
    let result = db
        .prepare("DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1")
        .bind(&[cutoff.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    let _ = result;
    Ok(rows.len() as u64)
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

async fn validate_organization_collections(
    db: &D1Database,
    user_id: &str,
    organization_id: &str,
    collection_ids: Vec<String>,
) -> Result<Vec<String>, AppError> {
    let member = super::organizations::load_membership(db, user_id, organization_id).await?;
    super::organizations::require_confirmed(&member)?;

    let mut seen = HashSet::new();
    let collection_ids = collection_ids
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect::<Vec<_>>();
    if collection_ids.is_empty()
        && !super::organizations::member_has_full_access(db, &member).await?
    {
        return Err(AppError::Forbidden(
            "A writable organization collection is required".to_string(),
        ));
    }
    for collection_id in &collection_ids {
        super::organizations::load_collection(db, organization_id, collection_id).await?;
        let (read_only, _, manage) =
            super::organizations::collection_permissions(db, &member, collection_id).await?;
        if read_only && !manage {
            return Err(AppError::Forbidden(
                "The selected organization collection is read-only".to_string(),
            ));
        }
    }
    Ok(collection_ids)
}

async fn finish_organization_cipher_mutation(
    db: &D1Database,
    state: &Arc<AppState>,
    organization_id: &str,
    acting_user_id: &str,
    cipher_id: &str,
    acting_device_id: Option<&str>,
    update_type: UpdateType,
) -> Result<(), AppError> {
    let revision = super::organizations::touch_organization_members(db, organization_id).await?;
    let members: Vec<Value> = db
        .prepare(
            "SELECT user_id FROM users_organizations
             WHERE organization_id = ?1 AND status = 2",
        )
        .bind(&[organization_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for member in members {
        let Some(user_id) = member.get("user_id").and_then(Value::as_str) else {
            continue;
        };
        notifications::publish_organization_cipher_update_background(
            &state.ctx,
            state.env.clone(),
            update_type,
            user_id.to_string(),
            cipher_id.to_string(),
            organization_id.to_string(),
            None,
            revision.clone(),
            (user_id == acting_user_id)
                .then(|| acting_device_id.map(str::to_string))
                .flatten(),
        );
    }
    Ok(())
}

pub(crate) async fn finish_organization_batch_mutation(
    db: &D1Database,
    state: &Arc<AppState>,
    organization_id: &str,
    acting_user_id: &str,
    acting_device_id: Option<&str>,
) -> Result<(), AppError> {
    let revision = super::organizations::touch_organization_members(db, organization_id).await?;
    let members: Vec<Value> = db
        .prepare(
            "SELECT user_id FROM users_organizations
             WHERE organization_id = ?1 AND status = 2",
        )
        .bind(&[organization_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for member in members {
        let Some(user_id) = member.get("user_id").and_then(Value::as_str) else {
            continue;
        };
        notifications::publish_user_update_background(
            &state.ctx,
            state.env.clone(),
            UpdateType::SyncCiphers,
            user_id.to_string(),
            revision.clone(),
            if user_id == acting_user_id {
                acting_device_id.map(str::to_string)
            } else {
                None
            },
        );
    }
    Ok(())
}

fn require_cipher_write(cipher: &CipherDBModel) -> Result<(), AppError> {
    if cipher.access_edit == Some(0) {
        Err(AppError::Forbidden(
            "This cipher is read-only for the current user".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn update_cipher_collections_inner(
    claims: &Claims,
    state: &Arc<AppState>,
    cipher_id: &str,
    data: CipherCollectionsData,
) -> Result<Cipher, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let existing = get_cipher_dbmodel(state, cipher_id, &claims.sub).await?;
    require_cipher_write(&existing)?;
    let organization_id = existing.organization_id.clone().ok_or_else(|| {
        AppError::BadRequest("Cipher is not owned by an organization".to_string())
    })?;

    let mut cipher: Cipher = existing.into();
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    let current = cipher
        .collection_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<HashSet<_>>();
    let posted = data.collection_ids.into_iter().collect::<HashSet<_>>();

    let member = super::organizations::load_membership(&db, &claims.sub, &organization_id).await?;
    super::organizations::require_confirmed(&member)?;
    let mut statements = Vec::new();
    for collection_id in posted.symmetric_difference(&current) {
        super::organizations::load_collection(&db, &organization_id, collection_id).await?;
        let (read_only, _, manage) =
            super::organizations::collection_permissions(&db, &member, collection_id).await?;
        if read_only && !manage {
            return Err(AppError::Forbidden(
                "No rights to modify the collection".to_string(),
            ));
        }
        if posted.contains(collection_id) {
            statements.push(
                db.prepare(
                    "INSERT OR IGNORE INTO ciphers_collections (cipher_id, collection_id)
                     VALUES (?1, ?2)",
                )
                .bind(&[cipher_id.into(), collection_id.clone().into()])?,
            );
        } else {
            statements.push(
                db.prepare(
                    "DELETE FROM ciphers_collections WHERE cipher_id = ?1 AND collection_id = ?2",
                )
                .bind(&[cipher_id.into(), collection_id.clone().into()])?,
            );
        }
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
        finish_organization_cipher_mutation(
            &db,
            state,
            &organization_id,
            &claims.sub,
            cipher_id,
            claims.device.as_deref(),
            UpdateType::SyncCipherUpdate,
        )
        .await?;
    }

    let refreshed = get_cipher_dbmodel(state, cipher_id, &claims.sub).await?;
    let mut cipher: Cipher = refreshed.into();
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    Ok(cipher)
}

pub(crate) async fn update_attachment_keys(
    db: &D1Database,
    cipher_id: &str,
    _user_id: &str,
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
            .prepare("SELECT cipher_id FROM cipher_attachments WHERE id = ?1")
            .bind(&[attachment_id.into()])?
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
        db.prepare("UPDATE cipher_attachments SET file_name = ?1, key = ?2, updated_at = ?3 WHERE id = ?4 AND cipher_id = ?5")
            .bind(&[
                file_name.into(),
                key.into(),
                db::now_rfc3339_millis().into(),
                attachment_id.into(),
                cipher_id.into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    }
    Ok(())
}

pub(crate) async fn get_cipher_dbmodel_with_access(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    organizations_enabled: bool,
) -> Result<crate::db::models::cipher::CipherDBModel, AppError> {
    db.prepare(accessible_cipher_sql(true))
        .bind(&[
            cipher_id.into(),
            user_id.into(),
            organizations_enabled.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::NotFound("Cipher not found".to_string()))
}

async fn get_cipher_dbmodel(
    state: &Arc<AppState>,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::db::models::cipher::CipherDBModel, AppError> {
    let db = db::get_db(&state.env)?;
    get_cipher_dbmodel_with_access(
        &db,
        cipher_id,
        user_id,
        super::organizations::organizations_enabled(&state.env),
    )
    .await
}

async fn create_cipher_inner(
    claims: Claims,
    state: &Arc<AppState>,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Cipher, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    cipher_data_req
        .validate_for_vault(&claims.sub)
        .map_err(|message| AppError::BadRequest(message.to_string()))?;
    let organization_id = cipher_data_req.organization_id.clone();
    let collection_ids = if let Some(organization_id) = organization_id.as_deref() {
        if !super::organizations::organizations_enabled(&state.env) {
            return Err(AppError::NotFound(
                "Organization support is disabled".to_string(),
            ));
        }
        validate_organization_collections(&db, &claims.sub, organization_id, collection_ids).await?
    } else {
        if !collection_ids.is_empty() {
            return Err(AppError::BadRequest(
                "Personal ciphers cannot be assigned to organization collections".to_string(),
            ));
        }
        Vec::new()
    };
    validate_folder(&db, cipher_data_req.folder_id.as_deref(), &claims.sub).await?;
    let now = now_string();
    let archived_at = normalize_optional_rfc3339(cipher_data_req.archived_date.as_deref());

    let cipher_data = CipherData::from_request(&cipher_data_req);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: organization_id.is_none().then(|| claims.sub.clone()),
        organization_id: organization_id.clone(),
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
        collection_ids: organization_id.as_ref().map(|_| collection_ids.clone()),
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    let is_organization_cipher = organization_id.is_some();
    let mut statements = vec![db
        .prepare(
            "INSERT INTO ciphers
             (id, user_id, organization_id, type, data, key, favorite, folder_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&[
            cipher.id.clone().into(),
            cipher.user_id.clone().into(),
            cipher.organization_id.clone().into(),
            cipher.r#type.into(),
            data.into(),
            cipher.key.clone().into(),
            (cipher.favorite && !is_organization_cipher).into(),
            if is_organization_cipher {
                None::<String>.into()
            } else {
                cipher.folder_id.clone().into()
            },
            cipher.created_at.clone().into(),
            cipher.updated_at.clone().into(),
        ])?];
    for collection_id in &collection_ids {
        statements.push(
            db.prepare(
                "INSERT INTO ciphers_collections (cipher_id, collection_id) VALUES (?1, ?2)",
            )
            .bind(&[cipher.id.clone().into(), collection_id.clone().into()])?,
        );
    }
    if is_organization_cipher && cipher.favorite {
        statements.push(
            db.prepare("INSERT INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                .bind(&[claims.sub.clone().into(), cipher.id.clone().into()])?,
        );
    }
    if is_organization_cipher && let Some(folder_id) = &cipher.folder_id {
        statements.push(
            db.prepare("INSERT INTO folders_ciphers (folder_id, cipher_id) VALUES (?1, ?2)")
                .bind(&[folder_id.clone().into(), cipher.id.clone().into()])?,
        );
    }
    db.batch(statements).await.map_err(|_| AppError::Database)?;

    if let Some(archived_at) = &archived_at {
        archive::save(&db, &claims.sub, &cipher.id, archived_at).await?;
    }

    if let Some(organization_id) = organization_id.as_deref() {
        finish_organization_cipher_mutation(
            &db,
            state,
            organization_id,
            &claims.sub,
            &cipher.id,
            claims.device.as_deref(),
            UpdateType::SyncCipherCreate,
        )
        .await?;
    } else {
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
    }
    attachments::enrich_cipher(&db, state, &mut cipher).await?;

    Ok(cipher)
}

async fn share_cipher_inner(
    claims: &Claims,
    state: &Arc<AppState>,
    cipher_id: &str,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Cipher, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    cipher_data_req
        .validate_for_vault(&claims.sub)
        .map_err(|message| AppError::BadRequest(message.to_string()))?;
    let organization_id = cipher_data_req
        .organization_id
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("An organizationId is required when sharing a cipher".to_string())
        })?;
    if !super::organizations::organizations_enabled(&state.env) {
        return Err(AppError::NotFound(
            "Organization support is disabled".to_string(),
        ));
    }

    let existing = get_cipher_dbmodel_with_access(&db, cipher_id, &claims.sub, true).await?;
    require_cipher_write(&existing)?;
    if existing
        .organization_id
        .as_deref()
        .is_some_and(|existing_org| existing_org != organization_id)
    {
        return Err(AppError::BadRequest(
            "Organization mismatch. Please resync the client before updating the cipher"
                .to_string(),
        ));
    }
    if client_revision_is_stale(
        &existing.updated_at,
        cipher_data_req.last_known_revision_date.as_deref(),
    ) {
        return Err(AppError::BadRequest(
            "The client copy of this cipher is out of date. Resync the client and try again."
                .to_string(),
        ));
    }
    let collection_ids =
        validate_organization_collections(&db, &claims.sub, &organization_id, collection_ids)
            .await?;
    validate_folder(&db, cipher_data_req.folder_id.as_deref(), &claims.sub).await?;

    let now = now_string();
    let requested_archived_at =
        normalize_optional_rfc3339(cipher_data_req.archived_date.as_deref());
    let archived_at = requested_archived_at
        .clone()
        .or_else(|| existing.archived_at.clone());
    let cipher_data = CipherData::from_request(&cipher_data_req);
    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;
    let data = serde_json::to_string(&data_value).map_err(|_| AppError::Internal)?;

    let mut statements = vec![
        db.prepare(
            "UPDATE ciphers
             SET user_id = NULL, organization_id = ?1, type = ?2, data = ?3, key = ?4,
                 favorite = 0, folder_id = NULL, updated_at = ?5
             WHERE id = ?6",
        )
        .bind(&[
            organization_id.clone().into(),
            cipher_data_req.r#type.into(),
            data.into(),
            cipher_data_req.key.clone().into(),
            now.clone().into(),
            cipher_id.into(),
        ])?,
    ];
    statements.push(
        db.prepare("DELETE FROM favorites WHERE user_id = ?1 AND cipher_id = ?2")
            .bind(&[claims.sub.clone().into(), cipher_id.into()])?,
    );
    statements.push(
        db.prepare("UPDATE cipher_attachments SET user_id = NULL WHERE cipher_id = ?1")
            .bind(&[cipher_id.into()])?,
    );
    statements.push(
        db.prepare(
            "DELETE FROM folders_ciphers WHERE cipher_id = ?1 AND folder_id IN
             (SELECT id FROM folders WHERE user_id = ?2)",
        )
        .bind(&[cipher_id.into(), claims.sub.clone().into()])?,
    );
    for collection_id in &collection_ids {
        statements.push(
            db.prepare(
                "INSERT OR IGNORE INTO ciphers_collections (cipher_id, collection_id)
                 VALUES (?1, ?2)",
            )
            .bind(&[cipher_id.into(), collection_id.clone().into()])?,
        );
    }
    if cipher_data_req.favorite {
        statements.push(
            db.prepare("INSERT INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                .bind(&[claims.sub.clone().into(), cipher_id.into()])?,
        );
    }
    if let Some(folder_id) = &cipher_data_req.folder_id {
        statements.push(
            db.prepare("INSERT INTO folders_ciphers (folder_id, cipher_id) VALUES (?1, ?2)")
                .bind(&[folder_id.clone().into(), cipher_id.into()])?,
        );
    }
    db.batch(statements).await.map_err(|_| AppError::Database)?;

    update_attachment_keys(
        &db,
        cipher_id,
        &claims.sub,
        cipher_data_req.attachments2.as_ref(),
    )
    .await?;

    if let Some(archived_at) = &requested_archived_at {
        archive::save(&db, &claims.sub, cipher_id, archived_at).await?;
    }
    let refreshed = get_cipher_dbmodel_with_access(&db, cipher_id, &claims.sub, true).await?;
    let mut cipher: Cipher = refreshed.into();
    cipher.archived_at = archived_at;
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    attachments::enrich_cipher(&db, state, &mut cipher).await?;
    finish_organization_cipher_mutation(
        &db,
        state,
        &organization_id,
        &claims.sub,
        cipher_id,
        claims.device.as_deref(),
        UpdateType::SyncCipherUpdate,
    )
    .await?;
    Ok(cipher)
}

#[worker::send]
pub async fn share_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(cipher_id): Path<String>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let cipher = share_cipher_inner(
        &claims,
        &state,
        &cipher_id,
        payload.cipher,
        payload.collection_ids,
    )
    .await?;
    let db = db::get_db(&state.env)?;
    super::events::log_event(
        &db,
        &state.env,
        1105,
        None,
        cipher.organization_id.as_deref(),
        Some(&cipher_id),
        &claims.sub,
    )
    .await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(cipher_id),
            detail: Some("Action: Share Cipher".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(cipher))
}

#[worker::send]
pub async fn share_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ShareSelectedCipherData>,
) -> Result<Json<()>, AppError> {
    if payload.ciphers.is_empty() {
        return Err(AppError::BadRequest(
            "You must select at least one cipher.".to_string(),
        ));
    }
    if payload.collection_ids.is_empty() {
        return Err(AppError::BadRequest(
            "You must select at least one collection.".to_string(),
        ));
    }
    if payload.ciphers.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 ciphers can be shared in one request".to_string(),
        ));
    }
    let count = payload.ciphers.len();
    for cipher in payload.ciphers {
        let cipher_id = cipher
            .id
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::BadRequest("Request missing ids field".to_string()))?;
        share_cipher_inner(
            &claims,
            &state,
            &cipher_id,
            cipher,
            payload.collection_ids.clone(),
        )
        .await?;
    }
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Share ({count} items)")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(()))
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

    let db = db::get_db(&state.env)?;
    super::events::log_event(
        &db,
        &state.env,
        1100,
        None,
        cipher.organization_id.as_deref(),
        Some(&cipher.id),
        &user_id,
    )
    .await?;

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
    let now = now_string();

    let existing_cipher = get_cipher_dbmodel_with_access(
        &db,
        &id,
        &claims.sub,
        super::organizations::organizations_enabled(&state.env),
    )
    .await?;
    require_cipher_write(&existing_cipher)?;

    let cipher_data_req = payload;
    cipher_data_req
        .validate_for_vault(&claims.sub)
        .map_err(|message| AppError::BadRequest(message.to_string()))?;
    if cipher_data_req.organization_id != existing_cipher.organization_id {
        return Err(AppError::BadRequest(
            "A cipher cannot be moved between personal and organization vaults by updating it"
                .to_string(),
        ));
    }
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

    let requested_archived_at =
        normalize_optional_rfc3339(cipher_data_req.archived_date.as_deref());
    let archived_at = requested_archived_at
        .clone()
        .or_else(|| existing_cipher.archived_at.clone());

    let cipher_data = CipherData::from_request(&cipher_data_req);

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: existing_cipher.user_id.clone(),
        organization_id: existing_cipher.organization_id.clone(),
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
        edit: existing_cipher.access_edit != Some(0),
        view_password: existing_cipher.access_view_password != Some(0),
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    if let Some(organization_id) = existing_cipher.organization_id.as_deref() {
        let mut statements = vec![
            db.prepare(
                "UPDATE ciphers SET type = ?1, data = ?2, key = ?3, updated_at = ?4
                 WHERE id = ?5 AND organization_id = ?6",
            )
            .bind(&[
                cipher.r#type.into(),
                data.into(),
                cipher.key.clone().into(),
                cipher.updated_at.clone().into(),
                id.clone().into(),
                organization_id.into(),
            ])?,
            db.prepare("DELETE FROM favorites WHERE user_id = ?1 AND cipher_id = ?2")
                .bind(&[claims.sub.clone().into(), id.clone().into()])?,
            db.prepare(
                "DELETE FROM folders_ciphers WHERE cipher_id = ?1 AND folder_id IN
                 (SELECT id FROM folders WHERE user_id = ?2)",
            )
            .bind(&[id.clone().into(), claims.sub.clone().into()])?,
        ];
        if cipher.favorite {
            statements.push(
                db.prepare("INSERT INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                    .bind(&[claims.sub.clone().into(), id.clone().into()])?,
            );
        }
        if let Some(folder_id) = &cipher.folder_id {
            statements.push(
                db.prepare("INSERT INTO folders_ciphers (folder_id, cipher_id) VALUES (?1, ?2)")
                    .bind(&[folder_id.clone().into(), id.clone().into()])?,
            );
        }
        db.batch(statements).await.map_err(|_| AppError::Database)?;
        update_attachment_keys(&db, &id, &claims.sub, cipher_data_req.attachments2.as_ref())
            .await?;
    } else {
        query!(
            &db,
            "UPDATE ciphers SET type = ?1, data = ?2, key = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
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

        update_attachment_keys(&db, &id, &claims.sub, cipher_data_req.attachments2.as_ref())
            .await?;
    }

    if let Some(archived_at) = &requested_archived_at {
        archive::save(&db, &claims.sub, &id, archived_at).await?;
    }

    if let Some(organization_id) = existing_cipher.organization_id.as_deref() {
        populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
        finish_organization_cipher_mutation(
            &db,
            &state,
            organization_id,
            &claims.sub,
            &cipher.id,
            claims.device.as_deref(),
            UpdateType::SyncCipherUpdate,
        )
        .await?;
    } else {
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
    }
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    super::events::log_event(
        &db,
        &state.env,
        1101,
        None,
        existing_cipher.organization_id.as_deref(),
        Some(&cipher.id),
        &claims.sub,
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
    require_cipher_write(&existing)?;

    if let Some(organization_id) = existing.organization_id.as_deref() {
        db.prepare(
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2
             WHERE id = ?3 AND organization_id = ?4",
        )
        .bind(&[
            now.clone().into(),
            now.clone().into(),
            id.clone().into(),
            organization_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    } else {
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

    let organization_id = existing.organization_id.clone();
    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = Some(now.clone());
    cipher.updated_at = now;
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    if let Some(organization_id) = organization_id.as_deref() {
        finish_organization_cipher_mutation(
            &db,
            &state,
            organization_id,
            &claims.sub,
            &id,
            claims.device.as_deref(),
            UpdateType::SyncCipherUpdate,
        )
        .await?;
    } else {
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
    }

    super::events::log_event(
        &db,
        &state.env,
        1115,
        None,
        organization_id.as_deref(),
        Some(&id),
        &claims.sub,
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
    require_cipher_write(&existing)?;

    if let Some(organization_id) = existing.organization_id.as_deref() {
        db.prepare(
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1
             WHERE id = ?2 AND organization_id = ?3",
        )
        .bind(&[
            now.clone().into(),
            id.clone().into(),
            organization_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    } else {
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

    let organization_id = existing.organization_id.clone();
    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = None;
    cipher.updated_at = now;
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

    if let Some(organization_id) = organization_id.as_deref() {
        finish_organization_cipher_mutation(
            &db,
            &state,
            organization_id,
            &claims.sub,
            &id,
            claims.device.as_deref(),
            UpdateType::SyncCipherUpdate,
        )
        .await?;
    } else {
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
    }

    super::events::log_event(
        &db,
        &state.env,
        1116,
        None,
        organization_id.as_deref(),
        Some(&id),
        &claims.sub,
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
    organizations_enabled: bool,
    archived_at: String,
) -> Result<Cipher, AppError> {
    let existing =
        get_cipher_dbmodel_with_access(db, cipher_id, user_id, organizations_enabled).await?;

    archive::save(db, user_id, cipher_id, &archived_at).await?;
    if existing.organization_id.is_none() {
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
    }

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = Some(archived_at.clone());
    if cipher.organization_id.is_none() {
        cipher.updated_at = archived_at;
    }
    populate_collection_ids(db, std::slice::from_mut(&mut cipher), user_id).await?;
    Ok(cipher)
}

async fn unarchive_cipher_record(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    organizations_enabled: bool,
    updated_at: String,
) -> Result<Cipher, AppError> {
    let existing =
        get_cipher_dbmodel_with_access(db, cipher_id, user_id, organizations_enabled).await?;

    archive::delete(db, user_id, cipher_id).await?;
    if existing.organization_id.is_none() {
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
    }

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = None;
    if cipher.organization_id.is_none() {
        cipher.updated_at = updated_at;
    }
    populate_collection_ids(db, std::slice::from_mut(&mut cipher), user_id).await?;
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

    let mut cipher = archive_cipher_record(
        &db,
        &id,
        &claims.sub,
        super::organizations::organizations_enabled(&state.env),
        now_string(),
    )
    .await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

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

    let mut cipher = unarchive_cipher_record(
        &db,
        &id,
        &claims.sub,
        super::organizations::organizations_enabled(&state.env),
        now_string(),
    )
    .await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

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
        let cipher = archive_cipher_record(
            &db,
            &id,
            &user_id,
            super::organizations::organizations_enabled(&state.env),
            now_string(),
        )
        .await?;
        ciphers.push(cipher);
    }
    attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

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
        let cipher = unarchive_cipher_record(
            &db,
            &id,
            &user_id,
            super::organizations::organizations_enabled(&state.env),
            now_string(),
        )
        .await?;
        ciphers.push(cipher);
    }
    attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

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
    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;
    require_cipher_write(&existing)?;
    let organization_id = existing.organization_id.clone();
    attachments::delete_cipher_attachments_from_r2(&state.env, &db, &id).await?;
    archive::delete(&db, &claims.sub, &id).await?;

    if let Some(organization_id) = organization_id.as_deref() {
        db.prepare("DELETE FROM ciphers WHERE id = ?1 AND organization_id = ?2")
            .bind(&[id.clone().into(), organization_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    } else {
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

    let revision = db::now_rfc3339_millis();
    if let Some(organization_id) = organization_id.as_deref() {
        finish_organization_cipher_mutation(
            &db,
            &state,
            organization_id,
            &claims.sub,
            &id,
            claims.device.as_deref(),
            UpdateType::SyncLoginDelete,
        )
        .await?;
    } else {
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
    }

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
    let mut organization_ids = HashSet::new();
    let mut changed_personal = false;
    for id in payload.ids {
        let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;
        require_cipher_write(&existing)?;
        if let Some(organization_id) = existing.organization_id {
            db.prepare(
                "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2
                 WHERE id = ?3 AND organization_id = ?4",
            )
            .bind(&[
                now.clone().into(),
                now.clone().into(),
                id.into(),
                organization_id.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
            organization_ids.insert(organization_id);
        } else {
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
            changed_personal = true;
        }
    }

    if changed_personal {
        finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;
    }
    for organization_id in organization_ids {
        finish_organization_batch_mutation(
            &db,
            &state,
            &organization_id,
            &claims.sub,
            claims.device.as_deref(),
        )
        .await?;
    }

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
    let mut organization_ids = HashSet::new();
    let mut changed_personal = false;
    for id in payload.ids {
        let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;
        require_cipher_write(&existing)?;
        if let Some(organization_id) = existing.organization_id.as_deref() {
            db.prepare(
                "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1
                 WHERE id = ?2 AND organization_id = ?3",
            )
            .bind(&[
                now.clone().into(),
                id.clone().into(),
                organization_id.into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
            organization_ids.insert(organization_id.to_string());
        } else {
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
            changed_personal = true;
        }
        let mut cipher: Cipher = existing.into();
        cipher.deleted_at = None;
        cipher.updated_at = now.clone();
        ciphers.push(cipher);
    }
    populate_collection_ids(&db, &mut ciphers, &claims.sub).await?;
    attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    if changed_personal {
        finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;
    }
    for organization_id in organization_ids {
        finish_organization_batch_mutation(
            &db,
            &state,
            &organization_id,
            &claims.sub,
            claims.device.as_deref(),
        )
        .await?;
    }

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
    let mut organization_ids = HashSet::new();
    let mut changed_personal = false;
    for id in payload.ids {
        let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;
        require_cipher_write(&existing)?;
        attachments::delete_cipher_attachments_from_r2(&state.env, &db, &id).await?;
        archive::delete(&db, &claims.sub, &id).await?;
        if let Some(organization_id) = existing.organization_id {
            db.prepare("DELETE FROM ciphers WHERE id = ?1 AND organization_id = ?2")
                .bind(&[id.into(), organization_id.clone().into()])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
            organization_ids.insert(organization_id);
        } else {
            query!(
                &db,
                "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
                id,
                claims.sub
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
            changed_personal = true;
        }
    }

    if changed_personal {
        finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;
    }
    for organization_id in organization_ids {
        finish_organization_batch_mutation(
            &db,
            &state,
            &organization_id,
            &claims.sub,
            claims.device.as_deref(),
        )
        .await?;
    }

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
        deserialize_with = "crate::db::models::cipher::deserialize_optional_nonempty_string"
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
    if payload.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 ciphers can be moved in one request".to_string(),
        ));
    }
    let mut ciphers = Vec::with_capacity(payload.ids.len());
    for id in &payload.ids {
        ciphers.push(get_cipher_dbmodel(&state, id, &claims.sub).await?);
    }
    let mut statements = Vec::new();
    for cipher in &ciphers {
        if cipher.organization_id.is_some() {
            statements.push(
                db.prepare(
                    "DELETE FROM folders_ciphers WHERE cipher_id = ?1 AND folder_id IN
                     (SELECT id FROM folders WHERE user_id = ?2)",
                )
                .bind(&[cipher.id.clone().into(), claims.sub.clone().into()])?,
            );
            if let Some(folder_id) = &payload.folder_id {
                statements.push(
                    db.prepare(
                        "INSERT INTO folders_ciphers (folder_id, cipher_id) VALUES (?1, ?2)",
                    )
                    .bind(&[folder_id.clone().into(), cipher.id.clone().into()])?,
                );
            }
        } else {
            statements.push(
                db.prepare(
                    "UPDATE ciphers SET folder_id = ?1, updated_at = ?2
                     WHERE id = ?3 AND user_id = ?4",
                )
                .bind(&[
                    payload.folder_id.clone().into(),
                    now.clone().into(),
                    cipher.id.clone().into(),
                    claims.sub.clone().into(),
                ])?,
            );
        }
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
    }

    finish_cipher_batch_mutation(&db, &state, &claims.sub, claims.device.as_deref()).await?;

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
        deserialize_with = "crate::db::models::cipher::deserialize_optional_nonempty_string"
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
    let mut ciphers = get_accessible_ciphers(
        &db,
        super::organizations::organizations_enabled(&state.env),
        &claims.sub,
    )
    .await?;
    attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_organization_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrganizationIdQuery>,
) -> Result<Json<Value>, AppError> {
    if !super::organizations::organizations_enabled(&state.env) {
        return Err(AppError::NotFound(
            "Organization support is disabled".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member =
        super::organizations::load_membership(&db, &claims.sub, &query.organization_id).await?;
    super::organizations::require_confirmed(&member)?;
    let mut ciphers = get_accessible_ciphers(&db, true, &claims.sub).await?;
    ciphers.retain(|cipher| cipher.organization_id.as_deref() == Some(&query.organization_id));
    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn bulk_update_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<BulkCollectionsData>,
) -> Result<Json<()>, AppError> {
    if data
        .cipher_ids
        .len()
        .saturating_mul(data.collection_ids.len())
        > 80
    {
        return Err(AppError::BadRequest(
            "The bulk collection operation is too large".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member =
        super::organizations::load_membership(&db, &claims.sub, &data.organization_id).await?;
    super::organizations::require_confirmed(&member)?;
    for collection_id in &data.collection_ids {
        super::organizations::load_collection(&db, &data.organization_id, collection_id).await?;
        let (read_only, _, manage) =
            super::organizations::collection_permissions(&db, &member, collection_id).await?;
        if read_only && !manage {
            return Err(AppError::NotFound(
                "User does not have write access to a collection".to_string(),
            ));
        }
    }
    let mut statements = Vec::new();
    for cipher_id in &data.cipher_ids {
        let Ok(cipher) = get_cipher_dbmodel_with_access(&db, cipher_id, &claims.sub, true).await
        else {
            continue;
        };
        if cipher.organization_id.as_deref() != Some(&data.organization_id)
            || require_cipher_write(&cipher).is_err()
        {
            continue;
        }
        for collection_id in &data.collection_ids {
            let statement = if data.remove_collections {
                db.prepare(
                    "DELETE FROM ciphers_collections WHERE cipher_id = ?1 AND collection_id = ?2",
                )
                .bind(&[cipher_id.clone().into(), collection_id.clone().into()])?
            } else {
                db.prepare(
                    "INSERT OR IGNORE INTO ciphers_collections (cipher_id, collection_id)
                     VALUES (?1, ?2)",
                )
                .bind(&[cipher_id.clone().into(), collection_id.clone().into()])?
            };
            statements.push(statement);
        }
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
        finish_organization_batch_mutation(
            &db,
            &state,
            &data.organization_id,
            &claims.sub,
            claims.device.as_deref(),
        )
        .await?;
    }
    Ok(Json(()))
}

#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let cipher = get_cipher_dbmodel_with_access(
        &db,
        &id,
        &claims.sub,
        super::organizations::organizations_enabled(&state.env),
    )
    .await?;
    let mut cipher: Cipher = cipher.into();
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;
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
pub async fn update_cipher_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<CipherCollectionsData>,
) -> Result<Json<Cipher>, AppError> {
    let cipher = update_cipher_collections_inner(&claims, &state, &id, data).await?;
    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher_collections_v2(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<CipherCollectionsData>,
) -> Result<Json<Value>, AppError> {
    let cipher = update_cipher_collections_inner(&claims, &state, &id, data).await?;
    Ok(Json(json!({
        "object": "optionalCipherDetails",
        "unavailable": false,
        "cipher": cipher
    })))
}

#[worker::send]
pub async fn update_cipher_collections_admin(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<CipherCollectionsData>,
) -> Result<Json<()>, AppError> {
    update_cipher_collections_inner(&claims, &state, &id, data).await?;
    Ok(Json(()))
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

    let now = now_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;
    let is_organization_cipher = existing.organization_id.is_some();

    if let Some(ref folder_id) = data.folder_id {
        let folder: Option<crate::db::models::folder::Folder> = db
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

    if is_organization_cipher {
        let mut statements = vec![
            db.prepare("DELETE FROM favorites WHERE user_id = ?1 AND cipher_id = ?2")
                .bind(&[claims.sub.clone().into(), id.clone().into()])?,
            db.prepare(
                "DELETE FROM folders_ciphers WHERE cipher_id = ?1 AND folder_id IN
                 (SELECT id FROM folders WHERE user_id = ?2)",
            )
            .bind(&[id.clone().into(), claims.sub.clone().into()])?,
        ];
        if data.favorite {
            statements.push(
                db.prepare("INSERT INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                    .bind(&[claims.sub.clone().into(), id.clone().into()])?,
            );
        }
        if let Some(folder_id) = &data.folder_id {
            statements.push(
                db.prepare("INSERT INTO folders_ciphers (folder_id, cipher_id) VALUES (?1, ?2)")
                    .bind(&[folder_id.clone().into(), id.clone().into()])?,
            );
        }
        db.batch(statements).await.map_err(|_| AppError::Database)?;
    } else {
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
    }

    let mut cipher: Cipher = existing.into();
    cipher.folder_id = data.folder_id;
    cipher.favorite = data.favorite;
    if !is_organization_cipher {
        cipher.updated_at = now;
    }
    populate_collection_ids(&db, std::slice::from_mut(&mut cipher), &claims.sub).await?;
    attachments::enrich_cipher(&db, &state, &mut cipher).await?;

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

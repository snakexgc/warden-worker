mod models;

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::{
    api::AppState,
    auth::Claims,
    db,
    db::models::{
        cipher::Cipher,
        folder::{Folder, FolderResponse},
        send::{SendDBModel, send_to_json},
        two_factor,
        user::User,
    },
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
    worker_runtime::domains,
};
use models::{Profile, SyncResponse, UserDecryption};

const KDF_TYPE_PBKDF2: i32 = 0;
const KDF_TYPE_ARGON2ID: i32 = 1;
const ARGON2ID_MEMORY_DEFAULT_MB: i32 = 64;
const ARGON2ID_PARALLELISM_DEFAULT: i32 = 4;

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    match kdf_type {
        KDF_TYPE_PBKDF2 => (None, None),
        KDF_TYPE_ARGON2ID => {
            if kdf_iterations < 1 {
                return (
                    Some(ARGON2ID_MEMORY_DEFAULT_MB),
                    Some(ARGON2ID_PARALLELISM_DEFAULT),
                );
            }
            let mem = kdf_memory.unwrap_or(ARGON2ID_MEMORY_DEFAULT_MB);
            let par = kdf_parallelism.unwrap_or(ARGON2ID_PARALLELISM_DEFAULT);
            let mem = if (15..=1024).contains(&mem) {
                mem
            } else {
                ARGON2ID_MEMORY_DEFAULT_MB
            };
            let par = if (1..=16).contains(&par) {
                par
            } else {
                ARGON2ID_PARALLELISM_DEFAULT
            };
            (Some(mem), Some(par))
        }
        _ => (None, None),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludeSubdomainsQuery {
    exclude_domains: Option<bool>,
}

#[worker::send]
pub async fn sync(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExcludeSubdomainsQuery>,
    headers: HeaderMap,
) -> Result<Json<SyncResponse>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user_id = claims.sub;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch personal and accessible organization ciphers in one authorization-aware query.
    let mut ciphers: Vec<Cipher> = super::get_accessible_ciphers(
        &db,
        super::super::organizations::organizations_enabled(&state.env),
        &user_id,
    )
    .await?;
    let show_ssh_keys = headers
        .get("bitwarden-client-version")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| semver::Version::parse(value).ok())
        .is_some_and(|version| version >= semver::Version::new(2024, 12, 0));
    if !show_ssh_keys {
        ciphers.retain(|cipher| cipher.r#type != 5);
    }
    super::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;

    let send_rows: Vec<Value> = db
        .prepare("SELECT * FROM sends WHERE user_id = ?1 ORDER BY updated_at DESC")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;
    let sends = send_rows
        .into_iter()
        .filter_map(|v| serde_json::from_value::<SendDBModel>(v).ok())
        .map(|s| send_to_json(&s))
        .collect::<Vec<_>>();

    let time = chrono::DateTime::parse_from_rfc3339(&user.created_at)
        .map_err(|_| AppError::Internal)?
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let user_key = user.key.clone();
    let user_email = user.email.clone();
    let (kdf_memory, kdf_parallelism) = normalize_kdf_for_response(
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
    );
    let account_keys = serde_json::json!({
        "publicKeyEncryptionKeyPair": {
            "wrappedPrivateKey": user.private_key.clone(),
            "publicKey": user.public_key.clone(),
            "signedPublicKey": null,
            "object": "publicKeyEncryptionKeyPair"
        },
        "securityState": null,
        "signatureKeyPair": null,
        "object": "privateKeys"
    });
    let profile = Profile {
        id: user.id,
        name: user.name.unwrap_or_default(),
        email: user_email.clone(),
        avatar_color: user.avatar_color,
        master_password_hint: user.master_password_hint,
        security_stamp: user.security_stamp,
        object: "profile".to_string(),
        premium: true,
        premium_from_organization: false,
        email_verified: user.email_verified,
        force_password_reset: false,
        two_factor_enabled: two_factor::is_any_enabled(&db, &user_id).await?,
        uses_key_connector: false,
        creation_date: time,
        key: user_key.clone(),
        private_key: user.private_key,
        culture: "en-US".to_string(),
        organizations: Vec::new(),
        providers: Vec::new(),
        provider_organizations: Vec::new(),
        account_keys,
    };

    let user_decryption = UserDecryption {
        master_password_unlock: serde_json::json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": kdf_memory,
                "parallelism": kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user_key,
            "masterKeyWrappedUserKey": user_key,
            "salt": user_email
        }),
    };

    let domains = if q.exclude_domains.unwrap_or(false) {
        Value::Null
    } else {
        domains::build_domains_object(&db, &user_id, true).await?
    };

    let organizations =
        super::super::organizations::profile_organizations(&db, &state.env, &user_id).await?;
    let collections =
        super::super::organizations::sync_collections(&db, &state.env, &user_id).await?;
    let policies = super::super::organizations::sync_policies(&db, &state.env, &user_id).await?;
    let premium_from_organization = !organizations.is_empty();

    let mut profile = profile;
    profile.organizations = organizations;
    profile.premium_from_organization = premium_from_organization;

    let response = SyncResponse {
        profile,
        folders,
        collections,
        policies,
        ciphers,
        sends,
        domains,
        user_decryption,
        object: "sync".to_string(),
    };

    // 发送同步通知 - 使用后台任务减少响应延迟
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::Sync,
        NotifyContext {
            user_id: Some(user_id),
            user_email: Some(user_email),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(response))
}

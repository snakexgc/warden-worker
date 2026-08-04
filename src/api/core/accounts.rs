pub mod devices;

pub use devices::*;

use axum::http::{HeaderMap, StatusCode};
use axum::{Json, extract::State};
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{Delay, query};

use crate::{
    api::AppState,
    auth::{Claims, InviteClaims, RegisterVerifyClaims},
    crypto::{self, KDF_TYPE_ARGON2ID, password},
    db,
    db::models::{
        cipher::{CipherData, CipherRequestData},
        send::SendData,
        two_factor,
        user::{KeyData, PreloginKdfSettings, PreloginResponse, RegisterRequest, User},
    },
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
};

const PROTECTED_ACTION_OTP_SIZE: u8 = 6;
const PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS: i64 = 30;
const REGISTER_ISSUER: &str = "warden-worker.register";
const INVITE_ISSUER: &str = "warden-worker.org-invite";

fn clean_password_hint(password_hint: Option<String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => {
            let ht = h.trim();
            if ht.is_empty() {
                None
            } else {
                Some(ht.to_string())
            }
        }
    }
}

fn validate_kdf(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> Result<(Option<i32>, Option<i32>), AppError> {
    crypto::validate_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        .map_err(AppError::BadRequest)?;

    // 返回标准化的参数
    Ok(crypto::normalize_kdf_params(
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    ))
}

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    crypto::normalize_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KdfData {
    #[serde(rename = "kdfType", alias = "kdf")]
    pub kdf: i32,
    #[serde(rename = "iterations", alias = "kdfIterations")]
    pub kdf_iterations: i32,
    #[serde(rename = "memory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "parallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(
        alias = "masterPasswordAuthenticationHash",
        alias = "MasterPasswordAuthenticationHash"
    )]
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(alias = "masterKeyWrappedUserKey", alias = "MasterKeyWrappedUserKey")]
    pub master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    #[serde(
        alias = "authenticationData",
        alias = "authentication_data",
        alias = "AuthenticationData"
    )]
    pub authentication_data: AuthenticationData,
    #[serde(alias = "unlockData", alias = "unlock_data", alias = "UnlockData")]
    pub unlock_data: UnlockData,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfFlatRequest {
    #[serde(alias = "kdfType")]
    pub kdf: i32,
    #[serde(alias = "kdfIterations", alias = "iterations")]
    pub kdf_iterations: i32,
    #[serde(alias = "kdfMemory", alias = "memory")]
    pub kdf_memory: Option<i32>,
    #[serde(alias = "kdfParallelism", alias = "parallelism")]
    pub kdf_parallelism: Option<i32>,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "newMasterPasswordHash", alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ChangeKdfPayload {
    Vw(ChangeKdfRequest),
    Flat(ChangeKdfFlatRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateUserAccountKeysRequest {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: RotateAccountKeys,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    #[serde(default)]
    emergency_access_unlock_data: Vec<Value>,
    master_password_unlock_data: RotateMasterPasswordUnlockData,
    #[serde(default)]
    organization_account_recovery_unlock_data: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateMasterPasswordUnlockData {
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_parallelism: Option<i32>,
    kdf_memory: Option<i32>,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountKeys {
    user_key_encrypted_account_private_key: String,
    account_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherRequestData>,
    folders: Vec<RotateFolderData>,
    sends: Vec<SendData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateFolderData {
    #[serde(default)]
    id: Option<String>,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    #[serde(alias = "key")]
    pub user_symmetric_key: String,
    #[serde(default)]
    pub user_asymmetric_keys: Option<KeyData>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    #[serde(alias = "key")]
    pub user_symmetric_key: String,
    pub token: NumberOrString,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::String(value) => value,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    pub avatar_color: Option<String>,
}

fn profile_json(user: User, two_factor_enabled: bool) -> Value {
    let account_keys = json!({
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

    json!({
        "id": user.id,
        "name": user.name.unwrap_or_default(),
        "email": user.email,
        "emailVerified": user.email_verified,
        "avatarColor": user.avatar_color,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "providers": [],
        "providerOrganizations": [],
        "forcePasswordReset": false,
        "usesKeyConnector": false,
        "creationDate": user.created_at,
        "_status": 0,
        "accountKeys": account_keys,
        "object": "profile"
    })
}

#[worker::send]
pub async fn profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let two_factor_enabled = two_factor::is_any_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    let user_id = user.id.clone();
    let mut response = profile_json(user, two_factor_enabled);
    let organizations =
        super::organizations::profile_organizations(&db, &state.env, &user_id).await?;
    response["premiumFromOrganization"] = json!(!organizations.is_empty());
    response["organizations"] = Value::Array(organizations);
    Ok(Json(response))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Value>, AppError> {
    let name = payload.name;

    if name.len() > 50 {
        return Err(AppError::BadRequest(
            "The field Name must be a string with a maximum length of 50.".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[name.into(), now.into(), claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let response = profile(claims, State(state)).await?;
    Ok(response)
}

#[worker::send]
pub async fn put_avatar(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AvatarData>,
) -> Result<Json<Value>, AppError> {
    if let Some(color) = payload.avatar_color.as_deref()
        && color.len() != 7
    {
        return Err(AppError::BadRequest(
            "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"
                .to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            to_js_val(payload.avatar_color),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let response = profile(claims, State(state)).await?;
    Ok(response)
}

#[worker::send]
pub async fn post_security_stamp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&db, &claims.sub, &payload).await?;
    let now = db::now_rfc3339_millis();
    let security_stamp = Uuid::new_v4().to_string();

    // Delete all devices for this user (matching vaultwarden behavior)
    db.prepare("DELETE FROM devices WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    db.prepare("UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            security_stamp.clone().into(),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor::is_any_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    let env = state.env.clone();
    let user_id = claims.sub.clone();
    let revision = user.updated_at.clone();
    state.ctx.wait_until(async move {
        if let Err(err) = crate::api::notifications::publish_user_update(
            &env,
            crate::api::notifications::UpdateType::LogOut,
            &user_id,
            &revision,
            None,
        )
        .await
        {
            log::warn!("failed to publish security-stamp logout: {err}");
        }
    });

    Ok(Json(profile_json(user, two_factor_enabled)))
}

#[worker::send]
pub async fn revision_date(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<i64>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let revision = db::get_user_revision(&db, &claims.sub).await?;
    let millis = chrono::DateTime::parse_from_rfc3339(&revision)
        .map_err(|_| AppError::Internal)?
        .timestamp_millis();
    Ok(Json(millis))
}

#[worker::send]
pub async fn prelogin(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = crate::auth::normalize_email(
        payload["email"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?,
    );
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }
    let db = db::get_db(&state.env)?;

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.clone().into()])?;
    let row: Option<Value> = query.first(None).await.map_err(|_| AppError::Database)?;
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = match row {
        Some(v) => {
            let kdf_type = v
                .get("kdf_type")
                .and_then(|x| x.as_i64())
                .unwrap_or(KDF_TYPE_ARGON2ID as i64) as i32;
            let kdf_iterations = v
                .get("kdf_iterations")
                .and_then(|x| x.as_i64())
                .unwrap_or(3) as i32;
            let kdf_memory = v
                .get("kdf_memory")
                .and_then(|x| x.as_i64())
                .map(|v| v as i32)
                .or(Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB));
            let kdf_parallelism = v
                .get("kdf_parallelism")
                .and_then(|x| x.as_i64())
                .map(|v| v as i32)
                .or(Some(crypto::ARGON2ID_PARALLELISM_DEFAULT));

            let kdf_name = match kdf_type {
                crypto::KDF_TYPE_PBKDF2 => "PBKDF2",
                crypto::KDF_TYPE_ARGON2ID => "Argon2id",
                _ => "Unknown",
            };
            log::info!(
                "[KDF] prelogin response for email={}: kdf_type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
                email,
                kdf_type,
                kdf_name,
                kdf_iterations,
                kdf_memory,
                kdf_parallelism
            );
            (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        }
        None => {
            log::info!(
                "[KDF] prelogin response for email={}: user not found, returning defaults (Argon2id)",
                email
            );
            (
                KDF_TYPE_ARGON2ID,
                3,
                Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB),
                Some(crypto::ARGON2ID_PARALLELISM_DEFAULT),
            )
        }
    };

    let (kdf_memory, kdf_parallelism) =
        normalize_kdf_for_response(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism);

    Ok(Json(PreloginResponse {
        kdf: kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        kdf_settings: PreloginKdfSettings {
            iterations: kdf_iterations,
            kdf_type,
            memory: kdf_memory,
            parallelism: kdf_parallelism,
        },
        salt: None,
    }))
}

#[worker::send]
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    log::info!(
        "Register payload: name={:?}, email={}",
        payload.name,
        payload.email
    );

    let db = db::get_db(&state.env)?;
    let email = crate::auth::normalize_email(&payload.email);
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }
    if !payload.current_format_is_valid(&email) {
        return Err(AppError::UnprocessableEntity(
            "Unexpected RegisterData format".to_string(),
        ));
    }

    let existing: Option<Value> = db
        .prepare("SELECT id, master_password_hash FROM users WHERE email = ?1")
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if existing
        .as_ref()
        .and_then(|row| row.get("master_password_hash"))
        .and_then(Value::as_str)
        .is_some_and(|hash| !hash.is_empty())
    {
        return Err(AppError::BadRequest(
            "Registration not allowed or user already exists".to_string(),
        ));
    }

    let invite_claims = validate_org_invite_registration(&state, &db, &payload, &email).await?;
    let verification = validate_registration_token(&state, &db, &payload, &email).await?;

    if invite_claims.is_none() {
        if !env_bool(&state.env, "SIGNUPS_ALLOWED", true) {
            return Err(AppError::BadRequest("Registration is disabled".to_string()));
        }
        ensure_email_allowed(&state.env, &email)?;
    }

    let signup_verification_required = env_bool(&state.env, "SIGNUPS_VERIFY", true);
    if signup_verification_required && invite_claims.is_none() && verification.is_none() {
        return Err(AppError::Unauthorized(
            "Email verification token is required".to_string(),
        ));
    }

    let registration_kdf = payload.kdf();
    let kdf_type = registration_kdf.kdf;
    let kdf_iterations = registration_kdf.kdf_iterations;
    let kdf_memory = registration_kdf.kdf_memory;
    let kdf_parallelism = registration_kdf.kdf_parallelism;
    let master_password_hash = payload.master_password_hash().to_string();
    let user_symmetric_key = payload.user_symmetric_key().to_string();

    let now = Utc::now().to_rfc3339();

    let name = verification
        .as_ref()
        .and_then(|(_, claims)| claims.name.clone())
        .filter(|name| !name.trim().is_empty())
        .or_else(|| payload.name.filter(|n| !n.trim().is_empty()))
        .unwrap_or_else(|| email.clone());

    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;

    let server_password = password::hash_password(&master_password_hash, None).await?;
    let master_password_hint = clean_password_hint(payload.master_password_hint);

    let user = User {
        id: existing
            .as_ref()
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        name: Some(name),
        email,
        email_verified: verification.is_some()
            || invite_claims.is_some()
            || !signup_verification_required,
        avatar_color: None,
        master_password_hash: server_password.hash,
        master_password_hint,
        key: user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        password_salt: Some(server_password.salt),
        password_iterations: Some(server_password.iterations),
        api_key: None,
        email_new: None,
        email_new_token: None,
        email_new_token_sent_at: None,
        created_at: now.clone(),
        updated_at: now,
    };

    let values = [
        user.id.clone().into(),
        to_js_val(user.name.clone()),
        user.email.clone().into(),
        user.email_verified.into(),
        to_js_val(user.avatar_color.clone()),
        user.master_password_hash.clone().into(),
        to_js_val(user.master_password_hint.clone()),
        user.key.clone().into(),
        user.private_key.clone().into(),
        user.public_key.clone().into(),
        user.kdf_type.into(),
        user.kdf_iterations.into(),
        to_js_val(user.kdf_memory),
        to_js_val(user.kdf_parallelism),
        user.security_stamp.clone().into(),
        to_js_val(user.password_salt.clone()),
        to_js_val(user.password_iterations),
        user.created_at.clone().into(),
        user.updated_at.clone().into(),
    ];

    let write_user = if existing.is_some() {
        db.prepare(
            "UPDATE users SET name = ?2, email = ?3, email_verified = ?4, avatar_color = ?5,
             master_password_hash = ?6, master_password_hint = ?7, key = ?8, private_key = ?9,
             public_key = ?10, kdf_type = ?11, kdf_iterations = ?12, kdf_memory = ?13,
             kdf_parallelism = ?14, security_stamp = ?15, password_salt = ?16,
             password_iterations = ?17, created_at = ?18, updated_at = ?19
             WHERE id = ?1 AND master_password_hash = ''",
        )
        .bind(&values)?
    } else {
        db.prepare(
            "INSERT INTO users (id, name, email, email_verified, avatar_color, master_password_hash,
             master_password_hint, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory,
             kdf_parallelism, security_stamp, password_salt, password_iterations, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )
        .bind(&values)?
    };

    let mut statements = vec![write_user];
    if let Some((token_hash, _)) = verification {
        statements.push(
            db.prepare(
                "UPDATE registration_tokens SET consumed_at = ?1
                 WHERE token_hash = ?2 AND consumed_at IS NULL",
            )
            .bind(&[user.updated_at.clone().into(), token_hash.into()])?,
        );
    }
    db.batch(statements).await.map_err(|error| {
        log::error!("Failed to register user: {error:?}");
        if error
            .to_string()
            .contains("UNIQUE constraint failed: users.email")
        {
            AppError::BadRequest("Registration not allowed or user already exists".to_string())
        } else {
            AppError::Database
        }
    })?;

    Ok(Json(json!({
        "object": "register",
        "captchaBypassToken": ""
    })))
}

fn env_bool(env: &worker::Env, name: &str, default: bool) -> bool {
    let value = env
        .var(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.secret(name).ok().map(|value| value.to_string()));
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

fn ensure_email_allowed(env: &worker::Env, email: &str) -> Result<(), AppError> {
    let allowed = env
        .secret("ALLOWED_EMAILS")
        .ok()
        .map(|value| value.to_string())
        .or_else(|| {
            env.var("ALLOWED_EMAILS")
                .ok()
                .map(|value| value.to_string())
        });
    let Some(allowed) = allowed.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    if allowed
        .split(',')
        .any(|candidate| crate::auth::normalize_email(candidate) == email)
    {
        Ok(())
    } else {
        Err(AppError::Unauthorized("Not allowed to signup".to_string()))
    }
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

async fn validate_registration_token(
    state: &AppState,
    db: &worker::D1Database,
    payload: &RegisterRequest,
    email: &str,
) -> Result<Option<(String, RegisterVerifyClaims)>, AppError> {
    use jsonwebtoken::{DecodingKey, Validation, decode};

    let Some(token) = payload.email_verification_token.as_deref() else {
        return Ok(None);
    };
    let claims = decode::<RegisterVerifyClaims>(
        token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid email verification token".to_string()))?
    .claims;
    if claims.iss != REGISTER_ISSUER || !claims.verified || claims.sub != email {
        return Err(AppError::Unauthorized(
            "Email verification token does not match email".to_string(),
        ));
    }
    let hash = token_hash(token);
    let now = Utc::now().to_rfc3339();
    let stored: Option<Value> = db
        .prepare(
            "SELECT id FROM registration_tokens
             WHERE token_hash = ?1 AND email = ?2 AND consumed_at IS NULL AND expires_at > ?3",
        )
        .bind(&[hash.clone().into(), email.into(), now.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if stored.is_none() {
        return Err(AppError::Unauthorized(
            "Email verification token is expired or already used".to_string(),
        ));
    }
    Ok(Some((hash, claims)))
}

async fn validate_org_invite_registration(
    state: &AppState,
    db: &worker::D1Database,
    payload: &RegisterRequest,
    email: &str,
) -> Result<Option<InviteClaims>, AppError> {
    use jsonwebtoken::{DecodingKey, Validation, decode};

    let (membership_id, token) = match (
        payload.organization_user_id.as_deref(),
        payload.org_invite_token.as_deref(),
    ) {
        (None, None) => return Ok(None),
        (Some(membership_id), Some(token)) => (membership_id, token),
        _ => {
            return Err(AppError::BadRequest(
                "Organization invitation is missing required parameters".to_string(),
            ));
        }
    };
    let claims = decode::<InviteClaims>(
        token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid organization invitation".to_string()))?
    .claims;
    if claims.iss != INVITE_ISSUER || claims.email != email || claims.member_id != membership_id {
        return Err(AppError::Unauthorized(
            "Organization invitation does not match registration".to_string(),
        ));
    }
    let membership: Option<Value> = db
        .prepare(
            "SELECT u.email FROM users_organizations m
             JOIN users u ON u.id = m.user_id
             WHERE m.id = ?1 AND m.organization_id = ?2 AND m.status = 0",
        )
        .bind(&[
            claims.member_id.clone().into(),
            claims.org_id.clone().into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if membership
        .as_ref()
        .and_then(|row| row.get("email"))
        .and_then(Value::as_str)
        != Some(email)
    {
        return Err(AppError::Unauthorized(
            "Organization invitation is no longer valid".to_string(),
        ));
    }
    Ok(Some(claims))
}

#[worker::send]
pub async fn change_master_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeMasterPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !password::verify_user_password(&db, &user.id, &payload.master_password_hash).await? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let master_password_hint = clean_password_hint(payload.master_password_hint.clone());
    let private_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_else(|| user.private_key.clone());
    let public_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_else(|| user.public_key.clone());
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let existing_salt = user.password_iterations.and(user.password_salt.as_deref());
    let server_password =
        password::hash_password(&payload.new_master_password_hash, existing_salt).await?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, security_stamp = ?10, updated_at = ?11, password_salt = ?12, password_iterations = ?13 WHERE id = ?14",
    )
    .bind(&[
        server_password.hash.into(),
        to_js_val(master_password_hint),
        payload.user_symmetric_key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.clone().into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    crate::api::notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        crate::api::notifications::UpdateType::LogOut,
        claims.sub.clone(),
        now,
        claims.device.clone(),
    );

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::PasswordChange,
        NotifyContext {
            user_id: Some(user.id),
            user_email: Some(user.email),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.new_email.trim().is_empty() {
        return Err(AppError::BadRequest("Missing newEmail".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let new_email = payload.new_email.to_lowercase();
    let supplied_token = payload.token.into_string();

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !password::verify_user_password(&db, &user.id, &payload.master_password_hash).await? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    if user.email_new.as_deref() != Some(new_email.as_str()) {
        return Err(AppError::BadRequest("Email change mismatch".to_string()));
    }
    let pending_token = user
        .email_new_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("No email change pending".to_string()))?;
    if !constant_time_eq::constant_time_eq(pending_token.as_bytes(), supplied_token.as_bytes()) {
        return Err(AppError::BadRequest("Token mismatch".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let existing_salt = user.password_iterations.and(user.password_salt.as_deref());
    let server_password =
        password::hash_password(&payload.new_master_password_hash, existing_salt).await?;

    db.prepare(
        "UPDATE users SET email = ?1, email_verified = ?2, master_password_hash = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, updated_at = ?10, password_salt = ?11, password_iterations = ?12, email_new = NULL, email_new_token = NULL, email_new_token_sent_at = NULL WHERE id = ?13",
    )
    .bind(&[
        new_email.clone().into(),
        true.into(),
        server_password.hash.into(),
        payload.user_symmetric_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.clone().into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Email already in use".to_string())
        } else {
            AppError::Database
        }
    })?;

    crate::api::notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        crate::api::notifications::UpdateType::LogOut,
        claims.sub.clone(),
        now,
        None,
    );

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::EmailChange,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(new_email),
            detail: Some("Action: Change Email".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeKdfPayload>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    let provided_old_hash = match &payload {
        ChangeKdfPayload::Vw(p) => &p.master_password_hash,
        ChangeKdfPayload::Flat(p) => &p.master_password_hash,
    };

    if !password::verify_user_password(&db, &user.id, provided_old_hash).await? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let (
        new_master_password_hash,
        key,
        kdf_type,
        kdf_iterations,
        kdf_memory_in,
        kdf_parallelism_in,
    ) = match &payload {
        ChangeKdfPayload::Vw(p) => {
            if p.authentication_data.kdf != p.unlock_data.kdf {
                return Err(AppError::BadRequest(
                    "KDF settings must be equal for authentication and unlock".to_string(),
                ));
            }

            if !user.email.eq_ignore_ascii_case(&p.authentication_data.salt)
                || !user.email.eq_ignore_ascii_case(&p.unlock_data.salt)
            {
                return Err(AppError::BadRequest(
                    "Invalid master password salt".to_string(),
                ));
            }

            (
                &p.authentication_data.master_password_authentication_hash,
                &p.unlock_data.master_key_wrapped_user_key,
                p.unlock_data.kdf.kdf,
                p.unlock_data.kdf.kdf_iterations,
                p.unlock_data.kdf.kdf_memory,
                p.unlock_data.kdf.kdf_parallelism,
            )
        }
        ChangeKdfPayload::Flat(p) => (
            &p.new_master_password_hash,
            &p.key,
            p.kdf,
            p.kdf_iterations,
            p.kdf_memory,
            p.kdf_parallelism,
        ),
    };

    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();

    let existing_salt = user.password_iterations.and(user.password_salt.as_deref());
    let server_password = password::hash_password(new_master_password_hash, existing_salt).await?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, kdf_type = ?3, kdf_iterations = ?4, kdf_memory = ?5, kdf_parallelism = ?6, security_stamp = ?7, updated_at = ?8, password_salt = ?9, password_iterations = ?10 WHERE id = ?11",
    )
    .bind(&[
        server_password.hash.into(),
        key.to_string().into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.clone().into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    crate::api::notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        crate::api::notifications::UpdateType::LogOut,
        claims.sub.clone(),
        now,
        claims.device.clone(),
    );

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::KdfChange,
        NotifyContext {
            user_id: Some(claims.sub.clone()),
            user_email: Some(user.email),
            detail: Some("Action: Change KDF settings".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

async fn owned_ids(
    db: &worker::D1Database,
    sql: &str,
    user_id: &str,
) -> Result<HashSet<String>, AppError> {
    let rows: Vec<Value> = db
        .prepare(sql)
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    rows.into_iter()
        .map(|row| {
            row.get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(AppError::Database)
        })
        .collect()
}

#[worker::send]
pub async fn rotate_user_account_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RotateUserAccountKeysRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !password::verify_user_password(
        &db,
        &claims.sub,
        &payload.old_master_key_authentication_hash,
    )
    .await?
    {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let unlock = &payload.account_unlock_data.master_password_unlock_data;
    if user.kdf_type != unlock.kdf_type
        || user.kdf_iterations != unlock.kdf_iterations
        || user.kdf_memory != unlock.kdf_memory
        || user.kdf_parallelism != unlock.kdf_parallelism
        || user.email != unlock.email
    {
        return Err(AppError::BadRequest(
            "Changing the KDF variant or email is not supported during key rotation".to_string(),
        ));
    }
    if user.public_key != payload.account_keys.account_public_key {
        return Err(AppError::BadRequest(
            "Changing the asymmetric keypair is not possible during key rotation".to_string(),
        ));
    }
    if !payload
        .account_unlock_data
        .emergency_access_unlock_data
        .is_empty()
        || !payload
            .account_unlock_data
            .organization_account_recovery_unlock_data
            .is_empty()
    {
        return Err(AppError::BadRequest(
            "Organization recovery and emergency access are not available in this personal vault"
                .to_string(),
        ));
    }

    let existing_ciphers = owned_ids(
        &db,
        "SELECT id FROM ciphers WHERE user_id = ?1",
        &claims.sub,
    )
    .await?;
    let existing_folders = owned_ids(
        &db,
        "SELECT id FROM folders WHERE user_id = ?1",
        &claims.sub,
    )
    .await?;
    let existing_sends =
        owned_ids(&db, "SELECT id FROM sends WHERE user_id = ?1", &claims.sub).await?;

    let provided_ciphers = payload
        .account_data
        .ciphers
        .iter()
        .filter_map(|cipher| cipher.id.clone())
        .collect::<HashSet<_>>();
    let provided_folders = payload
        .account_data
        .folders
        .iter()
        .filter_map(|folder| folder.id.clone())
        .collect::<HashSet<_>>();
    let provided_sends = payload
        .account_data
        .sends
        .iter()
        .filter_map(|send| send._id.clone())
        .collect::<HashSet<_>>();
    if !provided_ciphers.is_superset(&existing_ciphers) {
        return Err(AppError::BadRequest(
            "All existing ciphers must be included in the rotation".to_string(),
        ));
    }
    if !provided_folders.is_superset(&existing_folders) {
        return Err(AppError::BadRequest(
            "All existing folders must be included in the rotation".to_string(),
        ));
    }
    if !provided_sends.is_superset(&existing_sends) {
        return Err(AppError::BadRequest(
            "All existing sends must be included in the rotation".to_string(),
        ));
    }
    for cipher in &payload.account_data.ciphers {
        let id = cipher.id.as_ref().ok_or_else(|| {
            AppError::BadRequest("Cipher id is required during key rotation".to_string())
        })?;
        if !existing_ciphers.contains(id) {
            return Err(AppError::BadRequest("Cipher doesn't exist".to_string()));
        }
        cipher
            .validate_for_personal_vault(&claims.sub)
            .map_err(|message| AppError::BadRequest(message.to_string()))?;
    }
    if payload
        .account_data
        .folders
        .iter()
        .filter_map(|folder| folder.id.as_ref())
        .any(|id| !existing_folders.contains(id))
    {
        return Err(AppError::BadRequest("Folder doesn't exist".to_string()));
    }
    if payload
        .account_data
        .sends
        .iter()
        .filter_map(|send| send._id.as_ref())
        .any(|id| !existing_sends.contains(id))
    {
        return Err(AppError::BadRequest("Send doesn't exist".to_string()));
    }

    let now = db::now_rfc3339_millis();
    for folder in payload.account_data.folders {
        let Some(folder_id) = folder.id else {
            continue;
        };
        db.prepare("UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(&[
                folder.name.into(),
                now.clone().into(),
                folder_id.into(),
                claims.sub.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    }
    for send in payload.account_data.sends {
        crate::api::core::sends::rotate_send_data(&db, &claims.sub, send, &now).await?;
    }
    for cipher in payload.account_data.ciphers {
        let cipher_id = cipher.id.clone().ok_or(AppError::Internal)?;
        let data = serde_json::to_string(&CipherData::from_request(&cipher))
            .map_err(|_| AppError::Internal)?;
        db.prepare(
            "UPDATE ciphers SET type = ?1, data = ?2, key = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6
             WHERE id = ?7 AND user_id = ?8",
        )
        .bind(&[
            cipher.r#type.into(),
            data.into(),
            to_js_val(cipher.key.clone()),
            (if cipher.favorite { 1 } else { 0 }).into(),
            to_js_val(cipher.folder_id.clone()),
            now.clone().into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        crate::api::core::ciphers::update_attachment_keys(
            &db,
            &cipher_id,
            &claims.sub,
            cipher.attachments2.as_ref(),
        )
        .await?;
    }

    let server_password = password::hash_password(
        &unlock.master_key_authentication_hash,
        user.password_iterations.and(user.password_salt.as_deref()),
    )
    .await?;
    let security_stamp = Uuid::new_v4().to_string();
    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, private_key = ?3,
         security_stamp = ?4, password_salt = ?5, password_iterations = ?6, updated_at = ?7
         WHERE id = ?8",
    )
    .bind(&[
        server_password.hash.into(),
        unlock.master_key_encrypted_user_key.clone().into(),
        payload
            .account_keys
            .user_key_encrypted_account_private_key
            .into(),
        security_stamp.into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        now.clone().into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    crate::api::notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        crate::api::notifications::UpdateType::LogOut,
        claims.sub.clone(),
        now,
        claims.device.clone(),
    );
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::PasswordChange,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("Action: Rotate user account keys".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHintRequest {
    pub email: String,
}

#[worker::send]
pub async fn password_hint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordHintRequest>,
) -> Result<StatusCode, AppError> {
    crate::api::identity::enforce_unauthenticated_rate_limit(&state, &headers).await?;

    if !notify::is_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "This server is not configured to provide password hints.".to_string(),
        ));
    }

    let email = crate::auth::normalize_email(&payload.email);
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }

    let db = db::get_db(&state.env)?;
    let row: Option<Value> = db
        .prepare("SELECT master_password_hint FROM users WHERE email = ?1")
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    const NO_HINT: &str = "当前未配置密码提示词";
    let detail = match row {
        None => NO_HINT.to_string(),
        Some(row) => {
            let hint = row
                .get("master_password_hint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let hint = clean_password_hint(hint);
            hint.unwrap_or_else(|| NO_HINT.to_string())
        }
    };

    let sleep_ms = rand::thread_rng().gen_range(900..=1100);
    Delay::from(std::time::Duration::from_millis(sleep_ms as u64)).await;

    notify::send_password_hint_background(
        &state.ctx,
        state.env.clone(),
        NotifyContext {
            user_email: Some(email),
            detail: Some(detail.clone()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendVerificationEmailRequest {
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "receiveMarketingEmails")]
    pub _receive_marketing_emails: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOtpRequest {
    #[serde(rename = "OTP", alias = "otp")]
    pub otp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[worker::send]
pub async fn request_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    if let Some(existing) = two_factor::get_protected_action_otp(&db, &claims.sub).await? {
        let elapsed = Utc::now().timestamp().saturating_sub(existing.token_sent);
        if elapsed < PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS {
            return Err(AppError::BadRequest(format!(
                "Please wait {} seconds before requesting another code.",
                PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS - elapsed
            )));
        }
    }

    let user_row: Option<Value> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let email = user_row
        .and_then(|r| {
            r.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let token = two_factor::generate_email_token(PROTECTED_ACTION_OTP_SIZE);
    let otp_data = two_factor::ProtectedActionOtpData::new(token.clone());
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_protected_action_otp(&db, &claims.sub, &otp_data, &now).await?;

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email,
        token,
        notify::EmailType::TwoFactorLogin,
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    two_factor::validate_protected_action_otp(&db, &claims.sub, &payload.otp, true).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let master_password_hash = payload
        .master_password_hash
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing masterPasswordHash".to_string()))?;

    verify_user_password(&db, &claims.sub, master_password_hash).await?;

    Ok(Json(json!({ "Object": "masterPasswordPolicy" })))
}

#[worker::send]
pub async fn send_verification_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SendVerificationEmailRequest>,
) -> Result<Json<Value>, AppError> {
    use crate::auth::RegisterVerifyClaims;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};

    crate::api::identity::enforce_unauthenticated_rate_limit(&state, &headers).await?;

    log::info!(
        "Send verification email: name={:?}, email={}",
        payload.name,
        payload.email
    );

    let email = crate::auth::normalize_email(&payload.email);
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }
    if !env_bool(&state.env, "SIGNUPS_ALLOWED", true) {
        return Err(AppError::BadRequest("Registration is disabled".to_string()));
    }
    ensure_email_allowed(&state.env, &email)?;
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Registration notification channel is not configured".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    let active_user: Option<Value> = db
        .prepare(
            "SELECT 1 AS exists_user FROM users WHERE email = ?1 AND master_password_hash <> ''",
        )
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if active_user.is_some() {
        // Do not disclose whether an account exists.
        return Ok(Json(json!({})));
    }

    let jwt_keys = state.jwt_keys.clone();

    // Generate a token containing the name
    let now = Utc::now();
    let expires_at = now + Duration::hours(24);
    let exp = expires_at.timestamp() as usize;
    let token_id = Uuid::new_v4().to_string();

    let claims = RegisterVerifyClaims {
        sub: email.clone(),
        name: payload.name.filter(|n| !n.trim().is_empty()),
        exp,
        nbf: now.timestamp() as usize,
        iss: REGISTER_ISSUER.to_string(),
        jti: token_id.clone(),
        verified: true,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_keys.access_secret.as_ref()),
    )
    .map_err(|_| AppError::Internal)?;

    let token_hash = token_hash(&token);
    let now_text = now.to_rfc3339();
    db.batch(vec![
        db.prepare(
            "DELETE FROM registration_tokens
             WHERE email = ?1 AND (consumed_at IS NOT NULL OR expires_at <= ?2)",
        )
        .bind(&[email.clone().into(), now_text.clone().into()])?,
        db.prepare(
            "INSERT INTO registration_tokens
             (id, email, token_hash, expires_at, consumed_at, created_at)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
        )
        .bind(&[
            token_id.into(),
            email.clone().into(),
            token_hash.into(),
            expires_at.to_rfc3339().into(),
            now_text.into(),
        ])?,
    ])
    .await
    .map_err(|_| AppError::Database)?;

    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("email", &email)
        .append_pair("token", &token)
        .finish();
    let link = state.public_url(&format!("/#/finish-signup/?{query}"));
    let outbox_id = notify::enqueue_action_link(
        &state.env,
        &email,
        &link,
        notify::ActionLinkType::Registration,
        None,
    )
    .await?;
    notify::deliver_outbox_background(&state.ctx, state.env.clone(), outbox_id);

    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationVerificationClickedRequest {
    email: String,
    email_verification_token: String,
}

#[worker::send]
pub async fn registration_verification_clicked(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegistrationVerificationClickedRequest>,
) -> Result<Json<Value>, AppError> {
    use jsonwebtoken::{DecodingKey, Validation, decode};

    let token = decode::<RegisterVerifyClaims>(
        &payload.email_verification_token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid email verification token".to_string()))?;
    let email = crate::auth::normalize_email(&payload.email);
    if token.claims.iss != REGISTER_ISSUER || !token.claims.verified || token.claims.sub != email {
        return Err(AppError::Unauthorized("Email does not match".to_string()));
    }
    let db = db::get_db(&state.env)?;
    let valid: Option<Value> = db
        .prepare(
            "SELECT id FROM registration_tokens
             WHERE token_hash = ?1 AND email = ?2 AND consumed_at IS NULL AND expires_at > ?3",
        )
        .bind(&[
            token_hash(&payload.email_verification_token).into(),
            email.into(),
            Utc::now().to_rfc3339().into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if valid.is_none() {
        return Err(AppError::Unauthorized(
            "Email verification token is expired or already used".to_string(),
        ));
    }
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverData {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverTokenData {
    pub user_id: String,
    pub token: String,
}

#[worker::send]
pub async fn post_delete_recover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<DeleteRecoverData>,
) -> Result<Json<Value>, AppError> {
    crate::api::identity::enforce_unauthenticated_rate_limit(&state, &headers).await?;

    if notify::is_email_webhook_configured(&state.env) {
        let email = data.email.trim().to_lowercase();
        if !email.is_empty() {
            let db = db::get_db(&state.env)?;
            let user: Option<Value> = db
                .prepare("SELECT id FROM users WHERE email = ?1")
                .bind(&[email.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?;

            if let Some(user) = user
                && let Some(user_id) = user.get("id").and_then(|v| v.as_str())
            {
                log::info!("Delete recover requested for user {user_id}");
            }
        }

        Ok(Json(json!({})))
    } else {
        Err(AppError::BadRequest(
            "Please contact the administrator to delete your account".to_string(),
        ))
    }
}

#[worker::send]
pub async fn post_delete_recover_token(
    State(state): State<Arc<AppState>>,
    Json(data): Json<DeleteRecoverTokenData>,
) -> Result<Json<Value>, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let claims = crate::auth::decode_delete(&data.token, &jwt_keys.access_secret)?;

    if claims.sub != data.user_id {
        return Err(AppError::Unauthorized("Invalid claim".to_string()));
    }

    let db = db::get_db(&state.env)?;
    let user: Option<Value> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[data.user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if user.is_none() {
        return Err(AppError::NotFound("User doesn't exist".to_string()));
    }

    cascade_delete_user_data(&state.env, &db, &data.user_id).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_delete_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&db, &claims.sub, &payload).await?;
    cascade_delete_user_data(&state.env, &db, &claims.sub).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    post_delete_account(claims, State(state), Json(payload)).await
}

pub(crate) async fn validate_password_or_otp(
    db: &worker::D1Database,
    user_id: &str,
    payload: &SecretVerificationRequest,
) -> Result<(), AppError> {
    match (
        payload.master_password_hash.as_deref(),
        payload.otp.as_deref(),
    ) {
        (Some(master_password_hash), None) => {
            verify_user_password(db, user_id, master_password_hash).await
        }
        (None, Some(otp)) => {
            two_factor::validate_protected_action_otp(db, user_id, otp, true).await
        }
        _ => Err(AppError::BadRequest("No validation provided".to_string())),
    }
}

async fn verify_user_password(
    db: &worker::D1Database,
    user_id: &str,
    password_hash: &str,
) -> Result<(), AppError> {
    if !password::verify_user_password(db, user_id, password_hash).await? {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    Ok(())
}

async fn cascade_delete_user_data(
    env: &worker::Env,
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    crate::api::core::sends::delete_user_send_files_from_r2(env, db, user_id).await?;
    crate::api::core::ciphers::attachments::delete_user_attachments_from_r2(env, db, user_id)
        .await?;
    db.prepare("DELETE FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|e| {
            log::error!("Failed to cascade delete user {user_id}: {e:?}");
            AppError::Database
        })?;

    log::info!("User {user_id} and all associated data deleted");
    Ok(())
}

#[worker::send]
pub async fn get_tasks(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeysData {
    pub encrypted_private_key: String,
    pub public_key: String,
}

#[worker::send]
pub async fn post_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<KeysData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET private_key = ?1, public_key = ?2, updated_at = ?3 WHERE id = ?4")
        .bind(&[
            payload.encrypted_private_key.clone().into(),
            payload.public_key.clone().into(),
            now.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(json!({
        "privateKey": payload.encrypted_private_key,
        "publicKey": payload.public_key,
        "object": "keys"
    })))
}

#[worker::send]
pub async fn get_public_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Option<Value> = db
        .prepare("SELECT id, public_key FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let user = user.ok_or_else(|| AppError::NotFound("User doesn't exist".to_string()))?;
    let public_key = user
        .get("public_key")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::NotFound("User has no public_key".to_string()))?;
    Ok(Json(json!({
        "userId": user.get("id").cloned().unwrap_or(Value::Null),
        "publicKey": public_key,
        "object": "userKey"
    })))
}

#[worker::send]
pub async fn post_api_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    update_api_key(claims, state, payload, false).await
}

async fn update_api_key(
    claims: Claims,
    state: Arc<AppState>,
    payload: SecretVerificationRequest,
    rotate: bool,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&db, &claims.sub, &payload).await?;

    let existing: Option<String> = db
        .prepare("SELECT api_key FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("api_key"))
        .await
        .map_err(|_| AppError::Database)?;
    let api_key = if rotate || existing.as_deref().unwrap_or_default().is_empty() {
        crypto::generate_api_key()
    } else {
        existing.unwrap_or_default()
    };
    let now = db::now_rfc3339_millis();

    db.prepare("UPDATE users SET api_key = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            api_key.clone().into(),
            now.clone().into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(json!({
        "apiKey": api_key,
        "revisionDate": now,
        "object": "apiKey"
    })))
}

#[worker::send]
pub async fn rotate_api_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    update_api_key(claims, state, payload, true).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailTokenRequest {
    pub user_id: String,
    pub token: String,
}

#[worker::send]
pub async fn post_verify_email_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyEmailTokenRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    use jsonwebtoken::{DecodingKey, Validation, decode};

    let decoding_key = DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref());
    let token_data = decode::<crate::auth::BasicJwtClaims>(
        &payload.token,
        &decoding_key,
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid email verification token".to_string()))?;
    if token_data.claims.sub != payload.user_id
        || token_data.claims.iss != "warden-worker|verify-email"
    {
        return Err(AppError::Unauthorized("Invalid claim".to_string()));
    }

    let exists: Option<String> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[payload.user_id.clone().into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;
    if exists.is_none() {
        return Err(AppError::NotFound("User doesn't exist".to_string()));
    }
    let now = db::now_rfc3339_millis();
    db.prepare("UPDATE users SET email_verified = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[1.into(), now.into(), payload.user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_verify_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Cannot verify email address".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let email: String = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User doesn't exist".to_string()))?;
    let now = Utc::now();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &crate::auth::BasicJwtClaims {
            nbf: now.timestamp() as usize,
            exp: (now + chrono::Duration::minutes(10)).timestamp() as usize,
            iss: "warden-worker|verify-email".to_string(),
            sub: claims.sub,
        },
        &jsonwebtoken::EncodingKey::from_secret(state.jwt_keys.access_secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal)?;
    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email,
        token,
        notify::EmailType::VerifyEmail,
    );

    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailTokenRequest {
    pub master_password_hash: String,
    pub new_email: String,
}

#[worker::send]
pub async fn post_email_token(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EmailTokenRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let new_email = payload.new_email.to_lowercase();

    if !password::verify_user_password(&db, &claims.sub, &payload.master_password_hash).await? {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let existing: Option<Value> = db
        .prepare("SELECT id FROM users WHERE email = ?1 AND id != ?2")
        .bind(&[new_email.clone().into(), claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if existing.is_some() {
        return Err(AppError::BadRequest("Email already in use".to_string()));
    }

    let token = two_factor::generate_email_token(6);
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE users SET email_new = ?1, email_new_token = ?2, email_new_token_sent_at = ?3, updated_at = ?3 WHERE id = ?4",
    )
    .bind(&[
        new_email.clone().into(),
        token.clone().into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        new_email,
        token,
        notify::EmailType::ChangeEmail,
    );

    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordRequest {
    pub key: String,
    #[serde(default)]
    pub keys: Option<KeyData>,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[worker::send]
pub async fn post_set_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SetPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let user: Option<Value> = db
        .prepare("SELECT private_key FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if let Some(user) = user
        && let Some(private_key) = user.get("private_key").and_then(|v| v.as_str())
        && !private_key.is_empty()
    {
        return Err(AppError::BadRequest(
            "Account already initialized, cannot set password".to_string(),
        ));
    }

    let kdf_type = payload.kdf.unwrap_or(KDF_TYPE_ARGON2ID);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(3);
    let kdf_memory = payload
        .kdf_memory
        .or(Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB));
    let kdf_parallelism = payload
        .kdf_parallelism
        .or(Some(crypto::ARGON2ID_PARALLELISM_DEFAULT));
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)?;

    let server_password = password::hash_password(&payload.master_password_hash, None).await?;
    let master_password_hint = clean_password_hint(payload.master_password_hint);

    let private_key = payload
        .keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_default();
    let public_key = payload
        .keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_default();

    let now = Utc::now().to_rfc3339();
    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, password_salt = ?10, password_iterations = ?11, updated_at = ?12 WHERE id = ?13",
    )
    .bind(&[
        server_password.hash.into(),
        to_js_val(master_password_hint),
        payload.key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        server_password.salt.into(),
        server_password.iterations.into(),
        now.into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({
        "object": "set-password",
        "captchaBypassToken": ""
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_password_hint_none() {
        assert_eq!(clean_password_hint(None), None);
    }

    #[test]
    fn clean_password_hint_blank_to_none() {
        assert_eq!(clean_password_hint(Some("   ".to_string())), None);
    }

    #[test]
    fn clean_password_hint_trims() {
        assert_eq!(
            clean_password_hint(Some("  hint  ".to_string())),
            Some("hint".to_string())
        );
    }

    #[test]
    fn validate_kdf_pbkdf2_ok() {
        let (m, p) = validate_kdf(crypto::KDF_TYPE_PBKDF2, 600_000, Some(64), Some(4)).unwrap();
        assert_eq!(m, None);
        assert_eq!(p, None);
    }

    #[test]
    fn validate_kdf_pbkdf2_iterations_too_low() {
        assert!(validate_kdf(crypto::KDF_TYPE_PBKDF2, 99_999, None, None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_requires_params() {
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, None, Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_range_checks() {
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(14), Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(1025), Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(0)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(17)).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_ok() {
        let (m, p) = validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)).unwrap();
        assert_eq!(m, Some(64));
        assert_eq!(p, Some(4));
    }

    #[test]
    fn normalize_kdf_for_response_defaults_argon2id() {
        let (m, p) = normalize_kdf_for_response(crypto::KDF_TYPE_ARGON2ID, 3, None, None);
        assert_eq!(m, Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB));
        assert_eq!(p, Some(crypto::ARGON2ID_PARALLELISM_DEFAULT));
    }

    #[test]
    fn change_password_accepts_current_android_key_field() {
        let payload: ChangeMasterPasswordRequest = serde_json::from_value(json!({
            "masterPasswordHash": "old-hash",
            "newMasterPasswordHash": "new-hash",
            "masterPasswordHint": null,
            "key": "wrapped-user-key"
        }))
        .unwrap();

        assert_eq!(payload.user_symmetric_key, "wrapped-user-key");
    }

    #[test]
    fn profile_contains_current_bitwarden_non_null_contract_fields() {
        let profile = profile_json(
            User {
                id: "user-id".to_string(),
                name: None,
                email: "user@example.com".to_string(),
                email_verified: true,
                avatar_color: None,
                master_password_hash: "hash".to_string(),
                master_password_hint: None,
                key: "key".to_string(),
                private_key: "private".to_string(),
                public_key: "public".to_string(),
                kdf_type: 0,
                kdf_iterations: 600_000,
                kdf_memory: None,
                kdf_parallelism: None,
                security_stamp: "stamp".to_string(),
                password_salt: None,
                password_iterations: None,
                api_key: None,
                email_new: None,
                email_new_token: None,
                email_new_token_sent_at: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            },
            false,
        );
        assert_eq!(profile["_status"], 0);
        assert_eq!(profile["providers"], json!([]));
        assert_eq!(profile["providerOrganizations"], json!([]));
        assert_eq!(profile["forcePasswordReset"], false);
        assert_eq!(profile["usesKeyConnector"], false);
        assert_eq!(profile["creationDate"], "2026-01-01T00:00:00Z");
        assert_eq!(
            profile["accountKeys"]["publicKeyEncryptionKeyPair"]["wrappedPrivateKey"],
            "private"
        );
        assert_eq!(
            profile["accountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"],
            "public"
        );
        assert_eq!(profile["accountKeys"]["securityState"], Value::Null);
    }
}

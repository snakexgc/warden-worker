use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use data_encoding::BASE32;
use js_sys::Date;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};
use worker::D1Database;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rsa::{RsaPublicKey, BigUint, pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}};
use rsa::pkcs1v15::Pkcs1v15Sign;
use serde_cbor_2::Value as CborValue;

use crate::error::AppError;

pub const TWO_FACTOR_PROVIDER_AUTHENTICATOR: i32 = 0;
pub const TWO_FACTOR_PROVIDER_EMAIL: i32 = 1;
// 注意：2=Duo, 3=YubiKey, 4=U2f, 5=Remember, 6=OrganizationDuo, 7=Webauthn
pub const TWO_FACTOR_PROVIDER_WEBAUTHN: i32 = 7;
pub const TWO_FACTOR_PROVIDER_RECOVERY_CODE: i32 = 8;
pub const TWO_FACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE: i32 = 1002;
pub const TWO_FACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE: i32 = 1003;
pub const TWO_FACTOR_TYPE_WEBAUTHN_LOGIN_CHALLENGE: i32 = 1004;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredentialRecord {
    pub id: i32,
    pub name: String,
    pub migrated: bool,
    pub credential_id: String,
    #[serde(default)]
    pub public_key_sec1: Option<String>,
    #[serde(default)]
    pub sign_count: Option<u32>,
    #[serde(default)]
    pub key_type: Option<String>, // "ec" or "rsa"
}

fn decode_b64_mixed(input: &str) -> Result<Vec<u8>, AppError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| general_purpose::STANDARD.decode(input))
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn payload".to_string()))
}

fn rp_id_from_env(env: &worker::Env) -> String {
    env.var("DOMAIN")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn origin_from_env(env: &worker::Env) -> String {
    env.var("WEBAUTHN_ORIGIN")
        .ok()
        .map(|v| v.to_string())
        .or_else(|| env.var("DOMAIN").ok().map(|v| v.to_string()))
        .unwrap_or_default()
}

fn cbor_map_get<'a>(map: &'a std::collections::BTreeMap<CborValue, CborValue>, key: i128) -> Option<&'a CborValue> {
    map.get(&CborValue::Integer(key))
}

pub fn parse_webauthn_registration_attestation(
    attestation_object_b64: &str,
) -> Result<(String, String, u32, String), AppError> {
    let attestation_bytes = decode_b64_mixed(attestation_object_b64)?;
    let attestation_value: CborValue =
        serde_cbor_2::from_slice(&attestation_bytes).map_err(|_| AppError::BadRequest("Invalid WebAuthn attestation".to_string()))?;

    let auth_data = match attestation_value {
        CborValue::Map(map) => map
            .get(&CborValue::Text("authData".to_string()))
            .and_then(|v| match v {
                CborValue::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn attestation".to_string()))?,
        _ => return Err(AppError::BadRequest("Invalid WebAuthn attestation".to_string())),
    };

    if auth_data.len() < 37 {
        return Err(AppError::BadRequest("Invalid WebAuthn authenticatorData".to_string()));
    }

    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err(AppError::BadRequest("WebAuthn attested credential data missing".to_string()));
    }

    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    let mut idx = 37;
    if auth_data.len() < idx + 16 + 2 {
        return Err(AppError::BadRequest("Invalid WebAuthn authenticatorData".to_string()));
    }
    idx += 16;
    let cred_len = u16::from_be_bytes([auth_data[idx], auth_data[idx + 1]]) as usize;
    idx += 2;
    if auth_data.len() < idx + cred_len {
        return Err(AppError::BadRequest("Invalid WebAuthn credential id".to_string()));
    }

    let credential_id = &auth_data[idx..idx + cred_len];
    idx += cred_len;

    if auth_data.len() <= idx {
        return Err(AppError::BadRequest("Invalid WebAuthn credential public key".to_string()));
    }

    let mut deserializer = serde_cbor_2::de::Deserializer::from_slice(&auth_data[idx..]);
    let cose_value = CborValue::deserialize(&mut deserializer)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn credential public key".to_string()))?;

    match cose_value {
        CborValue::Map(map) => {
            let kty = cbor_map_get(&map, 1)
                .and_then(|v| match v {
                    CborValue::Integer(i) => Some(*i),
                    _ => None,
                })
                .unwrap_or_default();
            let alg = cbor_map_get(&map, 3)
                .and_then(|v| match v {
                    CborValue::Integer(i) => Some(*i),
                    _ => None,
                })
                .unwrap_or_default();

            // EC2 key type (elliptic curve)
            if kty == 2 && alg == -7 {
                let crv = cbor_map_get(&map, -1)
                    .and_then(|v| match v {
                        CborValue::Integer(i) => Some(*i),
                        _ => None,
                    })
                    .unwrap_or_default();
                if crv != 1 {
                    return Err(AppError::BadRequest("Unsupported WebAuthn curve".to_string()));
                }

                let x = cbor_map_get(&map, -2)
                    .and_then(|v| match v {
                        CborValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;
                let y = cbor_map_get(&map, -3)
                    .and_then(|v| match v {
                        CborValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn public key".to_string()))?;

                if x.len() != 32 || y.len() != 32 {
                    return Err(AppError::BadRequest("Invalid WebAuthn public key".to_string()));
                }

                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(&x);
                sec1.extend_from_slice(&y);

                return Ok((
                    general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                    general_purpose::URL_SAFE_NO_PAD.encode(sec1),
                    sign_count,
                    "ec".to_string(),
                ));
            }

            // RSA key type
            if kty == 3 && alg == -257 {
                let n = cbor_map_get(&map, -1)
                    .and_then(|v| match v {
                        CborValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn RSA public key".to_string()))?;
                let e = cbor_map_get(&map, -2)
                    .and_then(|v| match v {
                        CborValue::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| AppError::BadRequest("Invalid WebAuthn RSA public key".to_string()))?;

                // Build RSA public key and convert to PKCS#1 format
                let n_biguint = BigUint::from_bytes_be(&n);
                let e_biguint = BigUint::from_bytes_be(&e);
                let rsa_key = RsaPublicKey::new(n_biguint, e_biguint)
                    .map_err(|_| AppError::BadRequest("Invalid WebAuthn RSA public key".to_string()))?;

                // Export to PKCS#1 format
                let pkcs1_bytes = rsa_key.to_pkcs1_der()
                    .map_err(|_| AppError::BadRequest("Invalid WebAuthn RSA public key".to_string()))?;

                return Ok((
                    general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                    general_purpose::URL_SAFE_NO_PAD.encode(pkcs1_bytes.as_bytes()),
                    sign_count,
                    "rsa".to_string(),
                ));
            }

            Err(AppError::BadRequest("Unsupported WebAuthn algorithm".to_string()))
        }
        _ => Err(AppError::BadRequest("Invalid WebAuthn credential public key".to_string())),
    }
}

pub async fn ensure_two_factor_webauthn_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_webauthn (
            user_id TEXT PRIMARY KEY NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn ensure_two_factor_webauthn_challenge_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_webauthn_challenges (
            user_id TEXT NOT NULL,
            atype INTEGER NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, atype),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn get_webauthn_credentials(
    db: &D1Database,
    user_id: &str,
) -> Result<(bool, Vec<WebauthnCredentialRecord>), AppError> {
    ensure_two_factor_webauthn_table(db).await?;

    let result: Option<Value> = db
        .prepare("SELECT enabled, data FROM two_factor_webauthn WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = result else {
        return Ok((false, Vec::new()));
    };

    let enabled = row.get("enabled").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
    let raw = row.get("data").and_then(|v| v.as_str()).unwrap_or("[]");
    let creds = serde_json::from_str::<Vec<WebauthnCredentialRecord>>(raw).map_err(|_| AppError::Internal)?;
    Ok((enabled, creds))
}

pub async fn upsert_webauthn_credentials(
    db: &D1Database,
    user_id: &str,
    enabled: bool,
    credentials: &[WebauthnCredentialRecord],
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_webauthn_table(db).await?;
    let data = serde_json::to_string(credentials).map_err(|_| AppError::Internal)?;

    db.prepare(
        "INSERT INTO two_factor_webauthn (user_id, enabled, data, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET
            enabled = excluded.enabled,
            data = excluded.data,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        (if enabled { 1 } else { 0 }).into(),
        data.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

pub async fn delete_webauthn_credentials(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_webauthn_table(db).await?;
    db.prepare("DELETE FROM two_factor_webauthn WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn upsert_webauthn_challenge(
    db: &D1Database,
    user_id: &str,
    atype: i32,
    data: &str,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_webauthn_challenge_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_webauthn_challenges (user_id, atype, data, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id, atype) DO UPDATE SET
            data = excluded.data,
            updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        atype.into(),
        data.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn take_webauthn_challenge(
    db: &D1Database,
    user_id: &str,
    atype: i32,
) -> Result<Option<String>, AppError> {
    ensure_two_factor_webauthn_challenge_table(db).await?;
    let data: Option<String> = db
        .prepare("SELECT data FROM two_factor_webauthn_challenges WHERE user_id = ?1 AND atype = ?2")
        .bind(&[user_id.into(), atype.into()])?
        .first(Some("data"))
        .await
        .map_err(|_| AppError::Database)?;

    if data.is_some() {
        db.prepare("DELETE FROM two_factor_webauthn_challenges WHERE user_id = ?1 AND atype = ?2")
            .bind(&[user_id.into(), atype.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    }

    Ok(data)
}

pub async fn is_webauthn_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    Ok(get_webauthn_credentials(db, user_id).await?.0)
}

pub async fn generate_webauthn_login(
    db: &D1Database,
    env: &worker::Env,
    user_id: &str,
) -> Result<Value, AppError> {
    let creds = get_webauthn_credentials(db, user_id).await?.1;

    if creds.is_empty() {
        return Err(AppError::BadRequest("No WebAuthn devices registered".to_string()));
    }

    let mut challenge_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_bytes);
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    let app_id = format!(
        "{}/app-id.json",
        env.var("DOMAIN").ok().map(|v| v.to_string()).unwrap_or_default()
    );
    let rp_id = env
        .var("DOMAIN")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();

    let state_value = json!({
        "challenge": challenge,
        "kind": "webauthn.get"
    });

    let now = Utc::now().to_rfc3339();
    upsert_webauthn_challenge(
        db,
        user_id,
        TWO_FACTOR_TYPE_WEBAUTHN_LOGIN_CHALLENGE,
        &serde_json::to_string(&state_value).map_err(|_| AppError::Internal)?,
        &now,
    )
    .await?;

    // Build the WebAuthn authentication challenge response
    // This format matches what Bitwarden clients expect
    let mut response = json!({
        "challenge": state_value["challenge"],
        "timeout": 60000,
        "userVerification": "discouraged",
        "rpId": rp_id,
        "allowCredentials": creds
            .iter()
            .map(|c| json!({
                "type": "public-key",
                "id": c.credential_id,
                "transports": ["usb", "nfc", "ble", "internal"],
            }))
            .collect::<Vec<_>>(),
    });

    // Add extensions only if app_id is not empty
    if !app_id.is_empty() {
        response["extensions"] = json!({
            "appid": app_id,
        });
    }

    Ok(response)
}

pub async fn validate_webauthn_login(
    db: &D1Database,
    env: &worker::Env,
    user_id: &str,
    response: &str,
) -> Result<(), AppError> {
    let state_raw = take_webauthn_challenge(db, user_id, TWO_FACTOR_TYPE_WEBAUTHN_LOGIN_CHALLENGE)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let state: Value = serde_json::from_str(&state_raw).map_err(|_| AppError::Internal)?;
    let expected_challenge = state
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let rsp: Value = serde_json::from_str(response)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let credential_id = rsp
        .get("rawId")
        .and_then(|v| v.as_str())
        .or_else(|| rsp.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let client_data_b64 = rsp
        .get("response")
        .and_then(|v| v.get("clientDataJson").or_else(|| v.get("clientDataJSON")))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let client_data_raw = general_purpose::URL_SAFE_NO_PAD
        .decode(client_data_b64)
        .or_else(|_| general_purpose::STANDARD.decode(client_data_b64))
        .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
    let client_data: Value = serde_json::from_slice(&client_data_raw)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
    let typ = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let expected_origin = origin_from_env(env);
    if challenge != expected_challenge || typ != "webauthn.get" || (!expected_origin.is_empty() && origin != expected_origin) {
        return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
    }

    let authenticator_data_b64 = rsp
        .get("response")
        .and_then(|v| v.get("authenticatorData"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
    let signature_b64 = rsp
        .get("response")
        .and_then(|v| v.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let authenticator_data = decode_b64_mixed(authenticator_data_b64)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
    if authenticator_data.len() < 37 {
        return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
    }

    let rp_id = rp_id_from_env(env);
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    if !constant_time_eq::constant_time_eq(&authenticator_data[0..32], rp_id_hash.as_slice()) {
        return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
    }

    let flags = authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
    }
    let sign_count = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);

    let client_data_hash = Sha256::digest(&client_data_raw);
    let mut signed_data = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&client_data_hash);

    let signature = decode_b64_mixed(signature_b64)
        .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

    let mut registrations = get_webauthn_credentials(db, user_id).await?.1;
    if let Some(reg) = registrations.iter_mut().find(|r| r.credential_id == credential_id) {
        let Some(pk_b64) = reg.public_key_sec1.as_deref() else {
            return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
        };
        let public_key = decode_b64_mixed(pk_b64)
            .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;

        // Determine key type and verify accordingly
        let key_type = reg.key_type.as_deref().unwrap_or("ec");
        if key_type == "rsa" {
            // RSA signature verification
            let rsa_key = RsaPublicKey::from_pkcs1_der(&public_key)
                .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
            rsa_key
                .verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &signed_data, &signature)
                .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
        } else {
            // EC signature verification
            let ecdsa_sig = Signature::from_der(&signature)
                .or_else(|_| Signature::from_slice(&signature))
                .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
            let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
                .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
            verifying_key
                .verify(&signed_data, &ecdsa_sig)
                .map_err(|_| AppError::Unauthorized("Invalid two factor token.".to_string()))?;
        }

        if let Some(prev) = reg.sign_count {
            if prev > 0 && sign_count > 0 && sign_count <= prev {
                return Err(AppError::Unauthorized("Invalid two factor token.".to_string()));
            }
        }
        reg.sign_count = Some(sign_count);

        upsert_webauthn_credentials(db, user_id, true, &registrations, &Utc::now().to_rfc3339()).await?;
        return Ok(());
    }

    Err(AppError::Unauthorized("Invalid two factor token.".to_string()))
}

pub fn generate_totp_secret_base32_20() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    Secret::Raw(bytes.to_vec()).to_encoded().to_string()
}

pub async fn ensure_two_factor_authenticator_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_authenticator (
            user_id TEXT PRIMARY KEY NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            secret_enc TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn is_authenticator_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let enabled: Option<i64> = db
        .prepare("SELECT enabled FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(matches!(enabled, Some(1)))
}

pub async fn get_authenticator_secret_enc(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let secret_enc: Option<String> = db
        .prepare("SELECT secret_enc FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("secret_enc"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(secret_enc)
}

pub async fn upsert_authenticator_secret(
    db: &D1Database,
    user_id: &str,
    secret_enc: String,
    enabled: bool,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_authenticator (user_id, enabled, secret_enc, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET enabled = excluded.enabled, secret_enc = excluded.secret_enc, updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        (if enabled { 1 } else { 0 }).into(),
        secret_enc.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn disable_authenticator(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare("DELETE FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub fn encrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_encoded: &str,
) -> Result<String, AppError> {
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Ok(format!("plain:{}", secret_encoded));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret_encoded.as_bytes(),
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("gcm:{}", general_purpose::STANDARD.encode(blob)))
}

pub fn decrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_enc: &str,
) -> Result<String, AppError> {
    if let Some(rest) = secret_enc.strip_prefix("plain:") {
        return Ok(rest.to_string());
    }
    let Some(rest) = secret_enc.strip_prefix("gcm:") else {
        return Err(AppError::Internal);
    };
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Err(AppError::BadRequest("Missing TWO_FACTOR_ENC_KEY".to_string()));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()));
    }

    let blob = general_purpose::STANDARD
        .decode(rest)
        .map_err(|_| AppError::Internal)?;
    if blob.len() < 12 {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| {
            AppError::BadRequest(
                "Two-factor secret cannot be decrypted. Please regenerate the secret.".to_string(),
            )
        })?;

    Ok(String::from_utf8(pt).map_err(|_| AppError::Internal)?)
}

pub fn verify_totp_code(secret_encoded: &str, token: &str) -> Result<bool, AppError> {
    let token = token.trim();
    if token.len() != 6 || !token.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }

    let secret = Secret::Encoded(secret_encoded.to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| AppError::Internal)?,
        None,
        "".to_string(),
    )
    .map_err(|_| AppError::Internal)?;
    let unix_seconds = (Date::now() / 1000.0).floor() as u64;
    Ok(totp.check(token, unix_seconds))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTokenData {
    pub email: String,
    pub last_token: Option<String>,
    pub token_sent: i64,
    pub attempts: u64,
}

impl EmailTokenData {
    pub fn new(email: String, token: String) -> Self {
        Self {
            email,
            last_token: Some(token),
            token_sent: Utc::now().timestamp(),
            attempts: 0,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = Utc::now().timestamp();
    }

    pub fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }

    pub fn add_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn from_json(json_str: &str) -> Result<Self, AppError> {
        serde_json::from_str(json_str).map_err(|_| AppError::Internal)
    }
}

pub fn generate_email_token(token_size: u8) -> String {
    let mut rng = OsRng;
    let mut result = String::with_capacity(token_size as usize);
    for _ in 0..token_size {
        let digit = rng.next_u32() % 10;
        result.push(char::from(b'0' + digit as u8));
    }
    result
}

pub async fn ensure_two_factor_email_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_email (
            user_id TEXT PRIMARY KEY NOT NULL,
            atype INTEGER NOT NULL DEFAULT 1,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn get_email_2fa(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<(bool, String)>, AppError> {
    ensure_two_factor_email_table(db).await?;
    let result: Option<serde_json::Value> = db
        .prepare("SELECT enabled, data FROM two_factor_email WHERE user_id = ?1 AND atype = 1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    
    match result {
        Some(row) => {
            let enabled = row.get("enabled").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
            let data = row.get("data").and_then(|v| v.as_str()).unwrap_or("{}").to_string();
            Ok(Some((enabled, data)))
        }
        None => Ok(None),
    }
}

pub async fn is_email_2fa_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    match get_email_2fa(db, user_id).await? {
        Some((enabled, _)) => Ok(enabled),
        None => Ok(false),
    }
}

pub async fn upsert_email_2fa(
    db: &D1Database,
    user_id: &str,
    atype: i32,
    enabled: bool,
    data: &str,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_email (user_id, atype, enabled, data, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_id) DO UPDATE SET atype = excluded.atype, enabled = excluded.enabled, data = excluded.data, updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        atype.into(),
        (if enabled { 1 } else { 0 }).into(),
        data.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn delete_email_2fa(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    db.prepare("DELETE FROM two_factor_email WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn get_email_2fa_verification(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    ensure_two_factor_email_table(db).await?;
    let result: Option<serde_json::Value> = db
        .prepare("SELECT data FROM two_factor_email WHERE user_id = ?1 AND atype = ?2")
        .bind(&[user_id.into(), TWO_FACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    
    match result {
        Some(row) => {
            let data = row.get("data").and_then(|v| v.as_str()).unwrap_or("{}").to_string();
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

pub fn is_token_expired(token_sent: i64, max_seconds: i64) -> bool {
    let now = Utc::now().timestamp();
    now - token_sent > max_seconds
}

pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32.encode(&bytes)
}

pub async fn get_or_create_recovery_code(db: &D1Database, user_id: &str) -> Result<String, AppError> {
    let existing: Option<String> = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("totp_recover"))
        .await
        .map_err(|_| AppError::Database)?;
    
    if let Some(code) = existing {
        if !code.is_empty() {
            return Ok(code);
        }
    }
    
    let new_code = generate_recovery_code();
    let now = Utc::now().to_rfc3339();
    
    db.prepare("UPDATE users SET totp_recover = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[new_code.clone().into(), now.into(), user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    
    Ok(new_code)
}

pub async fn verify_recovery_code(db: &D1Database, user_id: &str, code: &str) -> Result<bool, AppError> {
    let stored: Option<String> = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("totp_recover"))
        .await
        .map_err(|_| AppError::Database)?;
    
    match stored {
        Some(stored_code) if !stored_code.is_empty() => {
            Ok(constant_time_eq::constant_time_eq(
                code.to_lowercase().as_bytes(),
                stored_code.to_lowercase().as_bytes(),
            ))
        }
        _ => Ok(false),
    }
}

pub async fn clear_recovery_code(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    
    db.prepare("UPDATE users SET totp_recover = NULL, updated_at = ?1 WHERE id = ?2")
        .bind(&[now.into(), user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    
    Ok(())
}

pub async fn delete_all_two_factors(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    disable_authenticator(db, user_id).await?;
    delete_email_2fa(db, user_id).await?;
    delete_webauthn_credentials(db, user_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generate_totp_secret_base32_20;
    use totp_rs::Secret;

    #[test]
    fn generated_totp_secret_is_20_bytes() {
        let secret = generate_totp_secret_base32_20();
        let bytes = Secret::Encoded(secret).to_bytes().expect("decode base32");
        assert_eq!(bytes.len(), 20);
    }
}

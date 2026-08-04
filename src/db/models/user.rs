use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: String,
    #[serde(with = "bool_from_int")]
    pub email_verified: bool,
    pub avatar_color: Option<String>,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub key: String,
    pub private_key: String,
    pub public_key: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    pub security_stamp: String,
    pub password_salt: Option<String>,
    pub password_iterations: Option<i32>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub email_new: Option<String>,
    #[serde(default)]
    pub email_new_token: Option<String>,
    #[serde(default)]
    pub email_new_token_sent_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

mod bool_from_int {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value {
            serializer.serialize_i64(1)
        } else {
            serializer.serialize_i64(0)
        }
    }
}

// For /accounts/prelogin response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    pub kdf_settings: PreloginKdfSettings,
    pub salt: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginKdfSettings {
    pub iterations: i32,
    pub kdf_type: i32,
    pub memory: Option<i32>,
    pub parallelism: Option<i32>,
}

// For /accounts/register request. Bitwarden 2026.5 moved the password
// authentication and unlock material into separate nested objects. Keep the
// legacy flat format so older clients remain compatible.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    #[serde(flatten)]
    credentials: RegisterCredentials,
    pub master_password_hint: Option<String>,
    pub user_asymmetric_keys: KeyData,
    #[serde(default)]
    pub email_verification_token: Option<String>,
    #[serde(default)]
    pub organization_user_id: Option<String>,
    #[serde(default)]
    pub org_invite_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterCredentials {
    Current(RegisterCredentialsCurrent),
    Legacy(RegisterCredentialsLegacy),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterCredentialsLegacy {
    #[serde(flatten)]
    kdf: RegisterKdfData,
    #[serde(alias = "userSymmetricKey")]
    key: String,
    master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterCredentialsCurrent {
    master_password_authentication: RegisterMasterPasswordAuthentication,
    master_password_unlock: RegisterMasterPasswordUnlock,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterMasterPasswordAuthentication {
    kdf: RegisterKdfData,
    salt: String,
    #[serde(alias = "masterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterMasterPasswordUnlock {
    kdf: RegisterKdfData,
    salt: String,
    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterKdfData {
    #[serde(rename = "kdfType", alias = "kdf")]
    pub kdf: i32,
    #[serde(rename = "iterations", alias = "kdfIterations")]
    pub kdf_iterations: i32,
    #[serde(default, rename = "memory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(default, rename = "parallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

impl RegisterRequest {
    pub fn master_password_hash(&self) -> &str {
        match &self.credentials {
            RegisterCredentials::Current(data) => &data.master_password_authentication.hash,
            RegisterCredentials::Legacy(data) => &data.master_password_hash,
        }
    }

    pub fn user_symmetric_key(&self) -> &str {
        match &self.credentials {
            RegisterCredentials::Current(data) => &data.master_password_unlock.key,
            RegisterCredentials::Legacy(data) => &data.key,
        }
    }

    pub fn kdf(&self) -> &RegisterKdfData {
        match &self.credentials {
            RegisterCredentials::Current(data) => &data.master_password_authentication.kdf,
            RegisterCredentials::Legacy(data) => &data.kdf,
        }
    }

    pub fn current_format_is_valid(&self, normalized_email: &str) -> bool {
        match &self.credentials {
            RegisterCredentials::Legacy(_) => true,
            RegisterCredentials::Current(data) => {
                data.master_password_authentication.kdf == data.master_password_unlock.kdf
                    && data.master_password_authentication.salt == normalized_email
                    && data.master_password_unlock.salt == normalized_email
            }
        }
    }
}

// Claims for email verification token
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    pub sub: String, // email
    pub name: Option<String>,
    pub exp: usize,
    pub nbf: usize,
    pub iss: String,
    pub jti: String,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub public_key: String,
    pub encrypted_private_key: String,
}

#[cfg(test)]
mod tests {
    use super::{PreloginKdfSettings, PreloginResponse, RegisterRequest};

    #[test]
    fn register_request_accepts_legacy_format() {
        let payload: RegisterRequest = serde_json::from_value(serde_json::json!({
            "name": "User",
            "email": "user@example.com",
            "masterPasswordHash": "hash",
            "masterPasswordHint": null,
            "userSymmetricKey": "wrapped-key",
            "userAsymmetricKeys": {
                "publicKey": "public",
                "encryptedPrivateKey": "private"
            },
            "kdf": 0,
            "kdfIterations": 600000,
            "kdfMemory": null,
            "kdfParallelism": null
        }))
        .expect("legacy registration payload should deserialize");

        assert_eq!(payload.master_password_hash(), "hash");
        assert_eq!(payload.user_symmetric_key(), "wrapped-key");
        assert!(payload.current_format_is_valid("user@example.com"));
    }

    #[test]
    fn register_request_accepts_current_format_and_validates_salts() {
        let payload: RegisterRequest = serde_json::from_value(serde_json::json!({
            "email": "user@example.com",
            "masterPasswordHint": null,
            "userAsymmetricKeys": {
                "publicKey": "public",
                "encryptedPrivateKey": "private"
            },
            "masterPasswordAuthentication": {
                "kdf": { "kdfType": 0, "iterations": 600000 },
                "salt": "user@example.com",
                "masterPasswordAuthenticationHash": "hash"
            },
            "masterPasswordUnlock": {
                "kdf": { "kdfType": 0, "iterations": 600000 },
                "salt": "user@example.com",
                "masterKeyWrappedUserKey": "wrapped-key"
            }
        }))
        .expect("current registration payload should deserialize");

        assert_eq!(payload.master_password_hash(), "hash");
        assert_eq!(payload.user_symmetric_key(), "wrapped-key");
        assert!(payload.current_format_is_valid("user@example.com"));
        assert!(!payload.current_format_is_valid("other@example.com"));
    }

    #[test]
    fn prelogin_response_contains_current_kdf_shape() {
        let value = serde_json::to_value(PreloginResponse {
            kdf: 1,
            kdf_iterations: 3,
            kdf_memory: Some(64),
            kdf_parallelism: Some(4),
            kdf_settings: PreloginKdfSettings {
                iterations: 3,
                kdf_type: 1,
                memory: Some(64),
                parallelism: Some(4),
            },
            salt: None,
        })
        .expect("serialize prelogin response");

        assert_eq!(value["kdfSettings"]["kdfType"], 1);
        assert_eq!(value["kdfSettings"]["iterations"], 3);
        assert_eq!(value["salt"], serde_json::Value::Null);
    }
}

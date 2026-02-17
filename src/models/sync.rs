use super::{cipher::Cipher, folder::FolderResponse};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDecryption {
    pub master_password_unlock: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub name: String,
    pub email: String,
    pub id: String,
    pub avatar_color: Option<String>,
    pub master_password_hint: Option<String>,
    pub security_stamp: String,
    pub object: String,
    pub premium_from_organization: bool,
    pub force_password_reset: bool,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub premium: bool,
    pub uses_key_connector: bool,
    pub creation_date: String,
    pub private_key: String,
    pub key: String,
    pub culture: String,
    pub organizations: Vec<Value>,
    pub providers: Vec<Value>,
    pub provider_organizations: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    pub folders: Vec<FolderResponse>,
    pub collections: Vec<Value>,
    pub policies: Vec<Value>,
    pub ciphers: Vec<Cipher>,
    pub sends: Vec<Value>,
    pub domains: Value,
    pub user_decryption: UserDecryption,
    pub object: String,
}

use serde::Deserialize;

/// D1 representation of Vaultwarden's device model.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub id: String,
    pub device_identifier: String,
    pub device_name: Option<String>,
    pub device_type: Option<i32>,
    pub remember_token_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

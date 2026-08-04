use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub cipher_id: String,
    pub file_name: String,
    pub size: i64,
    pub key: Option<String>,
    pub r2_object_key: String,
}

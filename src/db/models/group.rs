use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub access_all: i32,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Group {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "organizationId": self.organization_id,
            "name": self.name,
            "externalId": self.external_id,
            "object": "group"
        })
    }
}

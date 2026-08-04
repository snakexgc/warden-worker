use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Collection {
    pub fn to_json(&self) -> Value {
        json!({
            "externalId": self.external_id,
            "id": self.id,
            "organizationId": self.organization_id,
            "name": self.name,
            "type": 0,
            "defaultUserCollectionEmail": null,
            "object": "collection"
        })
    }

    pub fn to_details_json(&self, read_only: bool, hide_passwords: bool, manage: bool) -> Value {
        let mut value = self.to_json();
        value["object"] = json!("collectionDetails");
        value["readOnly"] = json!(read_only);
        value["hidePasswords"] = json!(hide_passwords);
        value["manage"] = json!(manage);
        value
    }
}

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize)]
pub struct OrgPolicy {
    pub id: String,
    pub organization_id: String,
    #[serde(rename = "type")]
    pub policy_type: i32,
    pub enabled: i32,
    pub data: String,
    pub created_at: String,
    pub updated_at: String,
}

impl OrgPolicy {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "organizationId": self.organization_id,
            "type": self.policy_type,
            "enabled": self.enabled != 0,
            "data": serde_json::from_str::<Value>(&self.data).unwrap_or(Value::Null),
            "object": "policy"
        });
        if self.policy_type == 8 {
            value["canToggleState"] = json!(true);
        }
        value
    }
}

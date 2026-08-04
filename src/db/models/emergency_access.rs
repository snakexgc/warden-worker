use serde::Deserialize;
use serde_json::{Value, json};

pub const EMERGENCY_TYPE_VIEW: i32 = 0;
pub const EMERGENCY_TYPE_TAKEOVER: i32 = 1;

pub const EMERGENCY_STATUS_INVITED: i32 = 0;
pub const EMERGENCY_STATUS_ACCEPTED: i32 = 1;
pub const EMERGENCY_STATUS_CONFIRMED: i32 = 2;
pub const EMERGENCY_STATUS_RECOVERY_INITIATED: i32 = 3;
pub const EMERGENCY_STATUS_RECOVERY_APPROVED: i32 = 4;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EmergencyAccess {
    pub id: String,
    pub grantor_uuid: String,
    pub grantee_uuid: Option<String>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,
    #[serde(rename = "type")]
    pub access_type: i32,
    pub status: i32,
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<String>,
    pub last_notification_at: Option<String>,
    pub updated_at: String,
    pub created_at: String,
}

impl EmergencyAccess {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "status": self.status,
            "type": self.access_type,
            "waitTimeDays": self.wait_time_days,
            "object": "emergencyAccess"
        })
    }

    pub fn is_approved_for(&self, user_id: &str, access_type: i32) -> bool {
        self.grantee_uuid.as_deref() == Some(user_id)
            && self.status == EMERGENCY_STATUS_RECOVERY_APPROVED
            && self.access_type == access_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> EmergencyAccess {
        EmergencyAccess {
            id: "ea".to_string(),
            grantor_uuid: "grantor".to_string(),
            grantee_uuid: Some("grantee".to_string()),
            email: None,
            key_encrypted: Some("2.key".to_string()),
            access_type: EMERGENCY_TYPE_VIEW,
            status: EMERGENCY_STATUS_RECOVERY_APPROVED,
            wait_time_days: 7,
            recovery_initiated_at: None,
            last_notification_at: None,
            updated_at: "now".to_string(),
            created_at: "now".to_string(),
        }
    }

    #[test]
    fn approved_access_checks_grantee_type_and_status() {
        assert!(record().is_approved_for("grantee", EMERGENCY_TYPE_VIEW));
        assert!(!record().is_approved_for("other", EMERGENCY_TYPE_VIEW));
        assert!(!record().is_approved_for("grantee", EMERGENCY_TYPE_TAKEOVER));
    }
}

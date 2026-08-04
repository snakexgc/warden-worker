use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: i32,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub cipher_id: Option<String>,
    pub collection_id: Option<String>,
    pub group_id: Option<String>,
    pub membership_id: Option<String>,
    pub device_type: Option<i32>,
    pub ip_address: Option<String>,
    pub acting_user_id: Option<String>,
    pub date: String,
}

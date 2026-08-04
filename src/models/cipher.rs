use chrono::{DateTime, SecondsFormat};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value, json};

// This struct represents the data stored in the `data` column of the `ciphers` table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_account: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drivers_license: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
}

impl CipherData {
    pub fn from_request(request: &CipherRequestData) -> Self {
        Self {
            name: request.name.clone(),
            notes: request.notes.clone(),
            login: request.login.clone(),
            card: request.card.clone(),
            identity: request.identity.clone(),
            secure_note: request.secure_note.clone(),
            ssh_key: request.ssh_key.clone(),
            bank_account: request.bank_account.clone(),
            drivers_license: request.drivers_license.clone(),
            passport: request.passport.clone(),
            fields: request.fields.clone(),
            password_history: request.password_history.clone(),
            reprompt: request.reprompt,
        }
    }
}

pub fn normalize_optional_rfc3339(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Micros, true))
}

pub fn client_revision_is_stale(server_revision: &str, client_revision: Option<&str>) -> bool {
    let Some(client_revision) = client_revision else {
        return false;
    };
    let (Ok(server_revision), Ok(client_revision)) = (
        DateTime::parse_from_rfc3339(server_revision),
        DateTime::parse_from_rfc3339(client_revision),
    ) else {
        return false;
    };

    server_revision
        .signed_duration_since(client_revision)
        .num_seconds()
        > 1
}

// Custom deserialization function for booleans
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    // A visitor is used to handle different data types
    struct BoolOrIntVisitor;

    impl<'de> de::Visitor<'de> for BoolOrIntVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer 0 or 1")
        }

        // Handles boolean values
        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        // Handles integer values (0 or 1)
        fn visit_u64<E>(self, value: u64) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Unsigned(value),
                    &"0 or 1",
                )),
            }
        }
    }

    deserializer.deserialize_any(BoolOrIntVisitor)
}

// Custom deserialization function for optional non-empty strings
// Converts empty strings to None to handle newer Bitwarden clients
pub fn deserialize_optional_nonempty_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
}

// The struct that is stored in the database and used in handlers.
// For serialization to JSON for the client, we implement a custom `Serialize`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub favorite: bool,
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,

    // Bitwarden specific field for API responses
    #[serde(default = "default_object")]
    pub object: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub organization_use_totp: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub edit: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub view_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(default)]
    pub attachments: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherDBModel {
    pub id: String,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub r#type: i32,
    pub data: String,
    #[serde(default)]
    pub key: Option<String>,
    pub favorite: i32,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub access_edit: Option<i32>,
    #[serde(default)]
    pub access_view_password: Option<i32>,
}

impl From<CipherDBModel> for Cipher {
    fn from(val: CipherDBModel) -> Self {
        Cipher {
            id: val.id,
            user_id: val.user_id,
            organization_id: val.organization_id,
            r#type: val.r#type,
            data: serde_json::from_str(&val.data).unwrap_or_default(),
            key: val.key,
            favorite: !matches!(val.favorite, 0),
            folder_id: val.folder_id,
            deleted_at: val.deleted_at,
            archived_at: val.archived_at,
            created_at: val.created_at,
            updated_at: val.updated_at,
            object: default_object(),
            organization_use_totp: true,
            edit: val.access_edit != Some(0),
            view_password: val.access_view_password != Some(0),
            collection_ids: None,
            attachments: None,
        }
    }
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut response_map = Map::new();
        let data_obj = self.data.as_object();
        let empty_data = Map::new();
        let data_obj = data_obj.unwrap_or(&empty_data);

        let name = data_obj.get("name").cloned().unwrap_or(Value::Null);
        let notes = data_obj.get("notes").cloned().unwrap_or(Value::Null);
        let fields = normalize_fields(data_obj.get("fields"));
        let password_history = normalize_password_history(data_obj.get("passwordHistory"));
        let reprompt = data_obj
            .get("reprompt")
            .and_then(Value::as_i64)
            .filter(|v| *v == 0 || *v == 1)
            .unwrap_or(0);

        let mut login = Value::Null;
        let mut secure_note = Value::Null;
        let mut card = Value::Null;
        let mut identity = Value::Null;
        let mut ssh_key = Value::Null;
        let mut bank_account = Value::Null;
        let mut drivers_license = Value::Null;
        let mut passport = Value::Null;

        match self.r#type {
            1 => {
                let mut value = data_obj.get("login").cloned().unwrap_or(Value::Null);
                normalize_login(&mut value);
                login = value;
            }
            2 => {
                let mut value = data_obj.get("secureNote").cloned().unwrap_or(Value::Null);
                normalize_secure_note(&mut value);
                secure_note = value;
            }
            3 => {
                card = data_obj.get("card").cloned().unwrap_or(Value::Null);
            }
            4 => {
                identity = data_obj.get("identity").cloned().unwrap_or(Value::Null);
            }
            5 => {
                let mut value = data_obj.get("sshKey").cloned().unwrap_or(Value::Null);
                normalize_ssh_key(&mut value);
                ssh_key = value;
            }
            6 => {
                bank_account = data_obj.get("bankAccount").cloned().unwrap_or(Value::Null);
            }
            7 => {
                drivers_license = data_obj
                    .get("driversLicense")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            8 => {
                passport = data_obj.get("passport").cloned().unwrap_or(Value::Null);
            }
            _ => {}
        }

        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map.insert("reprompt".to_string(), json!(reprompt));
        response_map.insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("key".to_string(), json!(self.key));
        response_map.insert(
            "attachments".to_string(),
            self.attachments.clone().unwrap_or(Value::Null),
        );
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map.insert(
            "collectionIds".to_string(),
            json!(self.collection_ids.clone().unwrap_or_default()),
        );
        response_map.insert("name".to_string(), name);
        response_map.insert("notes".to_string(), notes);
        response_map.insert("fields".to_string(), fields);
        response_map.insert("passwordHistory".to_string(), password_history);
        response_map.insert("login".to_string(), login);
        response_map.insert("secureNote".to_string(), secure_note);
        response_map.insert("card".to_string(), card);
        response_map.insert("identity".to_string(), identity);
        response_map.insert("sshKey".to_string(), ssh_key);
        response_map.insert("bankAccount".to_string(), bank_account);
        response_map.insert("driversLicense".to_string(), drivers_license);
        response_map.insert("passport".to_string(), passport);
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map.insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map.insert("viewPassword".to_string(), json!(self.view_password));
        response_map.insert(
            "permissions".to_string(),
            json!({ "delete": self.edit, "restore": self.edit }),
        );

        Value::Object(response_map).serialize(serializer)
    }
}

fn default_object() -> String {
    "cipherDetails".to_string()
}

fn default_true() -> bool {
    true
}

fn normalize_fields(value: Option<&Value>) -> Value {
    let Some(fields) = value.and_then(Value::as_array) else {
        return Value::Array(Vec::new());
    };

    Value::Array(
        fields
            .iter()
            .filter_map(|field| {
                let mut field = field.as_object()?.clone();
                match field.get("type") {
                    Some(Value::Number(_)) => {}
                    Some(Value::String(value)) => {
                        let field_type = value.parse::<u8>().unwrap_or(1);
                        field.insert("type".to_string(), json!(field_type));
                    }
                    _ => {
                        field.insert("type".to_string(), json!(1));
                    }
                }
                Some(Value::Object(field))
            })
            .collect(),
    )
}

fn normalize_password_history(value: Option<&Value>) -> Value {
    let Some(history) = value.and_then(Value::as_array) else {
        return Value::Array(Vec::new());
    };

    Value::Array(
        history
            .iter()
            .filter_map(|entry| {
                let mut entry = entry.as_object()?.clone();
                if !entry.get("password").is_some_and(Value::is_string) {
                    return None;
                }

                let last_used_date = entry
                    .get("lastUsedDate")
                    .and_then(Value::as_str)
                    .and_then(|value| normalize_optional_rfc3339(Some(value)))
                    .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());
                entry.insert("lastUsedDate".to_string(), json!(last_used_date));
                Some(Value::Object(entry))
            })
            .collect(),
    )
}

fn normalize_login(login: &mut Value) {
    let Value::Object(map) = login else {
        return;
    };

    if let Some(uris) = map.get_mut("uris").and_then(Value::as_array_mut) {
        for uri in uris {
            let Some(uri) = uri.as_object_mut() else {
                continue;
            };
            if let Some(Value::String(match_value)) = uri.get("match") {
                let match_value = match_value.parse::<u8>().map_or(Value::Null, |v| json!(v));
                uri.insert("match".to_string(), match_value);
            }
        }
    }

    if let Some(Value::String(password_revision_date)) = map.get("passwordRevisionDate") {
        let password_revision_date = normalize_optional_rfc3339(Some(password_revision_date))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());
        map.insert(
            "passwordRevisionDate".to_string(),
            json!(password_revision_date),
        );
    }

    let first_uri = map
        .get("uris")
        .and_then(Value::as_array)
        .and_then(|uris| uris.first())
        .and_then(|uri| uri.get("uri"))
        .cloned();

    map.insert("uri".to_string(), first_uri.unwrap_or(Value::Null));
}

fn normalize_ssh_key(ssh_key: &mut Value) {
    let is_valid = ssh_key.as_object().is_some_and(|ssh_key| {
        ["keyFingerprint", "privateKey", "publicKey"]
            .iter()
            .all(|field| {
                ssh_key
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
    });

    if !is_valid {
        *ssh_key = Value::Null;
    }
}

fn normalize_secure_note(secure_note: &mut Value) {
    let has_numeric_type = secure_note
        .as_object()
        .and_then(|map| map.get("type"))
        .is_some_and(Value::is_number);

    if !has_numeric_type {
        *secure_note = json!({ "type": 0 });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cipher, CipherDBModel, CipherData, CipherRequestFlat, CreateCipherRequest,
        client_revision_is_stale, normalize_optional_rfc3339,
    };
    use serde_json::{Value, json};

    #[test]
    fn cipher_serialization_matches_current_details_shape() {
        let cipher = Cipher {
            id: "test-id".to_string(),
            user_id: Some("user-1".to_string()),
            organization_id: None,
            r#type: 1,
            data: json!({
                "name": "Example",
                "notes": null,
                "login": { "username": "u", "password": "p" }
            }),
            key: Some("2.cipher-key".to_string()),
            favorite: false,
            folder_id: None,
            deleted_at: None,
            archived_at: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
            object: "cipherDetails".to_string(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        };

        let value = serde_json::to_value(cipher).expect("serialize cipher");

        let permissions = value
            .get("permissions")
            .and_then(Value::as_object)
            .expect("permissions object");

        assert_eq!(
            permissions.get("delete"),
            Some(&Value::Bool(true)),
            "permissions.delete must exist and be true when edit=true"
        );
        assert_eq!(
            permissions.get("restore"),
            Some(&Value::Bool(true)),
            "permissions.restore must exist and be true when edit=true"
        );
        assert_eq!(value.get("archivedDate"), Some(&Value::Null));
        assert_eq!(value.get("object"), Some(&json!("cipherDetails")));
        assert_eq!(value.get("key"), Some(&json!("2.cipher-key")));
        assert_eq!(value.get("collectionIds"), Some(&json!([])));
        assert_eq!(value.get("fields"), Some(&json!([])));
        assert_eq!(value.get("bankAccount"), Some(&Value::Null));
        assert_eq!(value.get("driversLicense"), Some(&Value::Null));
        assert_eq!(value.get("passport"), Some(&Value::Null));
        assert!(
            value.get("data").is_none(),
            "current cipherDetails responses must not expose the legacy data field"
        );
        assert_eq!(value.pointer("/login/uri"), Some(&Value::Null));
        assert!(
            value.get("userId").is_none(),
            "vaultwarden cipherDetails responses do not expose userId"
        );
    }

    #[test]
    fn cipher_db_model_preserves_key_in_api_response() {
        let row = json!({
            "id": "cipher-1",
            "user_id": "user-1",
            "organization_id": null,
            "type": 1,
            "data": "{\"name\":\"2.name\",\"login\":{}}",
            "key": "2.cipher-key",
            "favorite": 0,
            "folder_id": null,
            "deleted_at": null,
            "archived_at": null,
            "created_at": "2026-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z"
        });

        let db_model: CipherDBModel = serde_json::from_value(row).expect("deserialize D1 row");
        let response = serde_json::to_value(Cipher::from(db_model)).expect("serialize cipher");

        assert_eq!(response.get("key"), Some(&json!("2.cipher-key")));
    }

    #[test]
    fn create_cipher_request_deserializes_camelcase() {
        let body = json!({
            "cipher": { "type": 1, "name": "n", "key": "2.cipher-key" },
            "collectionIds": ["c1", "c2"]
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.r#type, 1);
        assert_eq!(req.cipher.name, "n");
        assert_eq!(req.cipher.key.as_deref(), Some("2.cipher-key"));
        assert_eq!(req.collection_ids, vec!["c1".to_string(), "c2".to_string()]);
    }

    #[test]
    fn flat_cipher_request_preserves_key() {
        let body = json!({
            "type": 1,
            "name": "2.name",
            "key": "2.cipher-key",
            "collectionIds": []
        });

        let req: CipherRequestFlat = serde_json::from_value(body).expect("deserialize");

        assert_eq!(req.cipher.key.as_deref(), Some("2.cipher-key"));
    }

    #[test]
    fn current_android_ssh_key_request_round_trips_all_core_data() {
        let body = json!({
            "type": 5,
            "name": "2.name",
            "key": "2.cipher-key",
            "sshKey": {
                "publicKey": "2.public",
                "privateKey": "2.private",
                "keyFingerprint": "2.fingerprint"
            },
            "attachments2": {},
            "bankAccount": null,
            "driversLicense": null,
            "passport": null,
            "encryptedFor": "user-1",
            "collectionIds": []
        });

        let req: CipherRequestFlat = serde_json::from_value(body).expect("deserialize");
        req.cipher
            .validate_for_personal_vault("user-1")
            .expect("valid SSH key request");
        let stored = serde_json::to_value(CipherData::from_request(&req.cipher))
            .expect("serialize stored cipher data");

        assert_eq!(
            stored.pointer("/sshKey/publicKey"),
            Some(&json!("2.public"))
        );
        assert_eq!(
            stored.pointer("/sshKey/privateKey"),
            Some(&json!("2.private"))
        );
        assert_eq!(
            stored.pointer("/sshKey/keyFingerprint"),
            Some(&json!("2.fingerprint"))
        );

        let response = serde_json::to_value(Cipher {
            id: "ssh-1".to_string(),
            user_id: Some("user-1".to_string()),
            organization_id: None,
            r#type: 5,
            data: stored,
            key: Some("2.cipher-key".to_string()),
            favorite: false,
            folder_id: None,
            deleted_at: None,
            archived_at: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
            object: "cipherDetails".to_string(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        })
        .expect("serialize SSH cipher response");
        assert_eq!(
            response.pointer("/sshKey/publicKey"),
            Some(&json!("2.public"))
        );
        assert_eq!(response.get("key"), Some(&json!("2.cipher-key")));
    }

    #[test]
    fn cipher_validation_rejects_blank_and_accepts_current_types() {
        let missing_login: CipherRequestFlat = serde_json::from_value(json!({
            "type": 1,
            "name": "2.name"
        }))
        .expect("deserialize missing login request");
        assert_eq!(
            missing_login.cipher.validate_for_personal_vault("user-1"),
            Err("Cipher type data is missing")
        );

        let future_type: CipherRequestFlat = serde_json::from_value(json!({
            "type": 6,
            "name": "2.name",
            "bankAccount": { "accountNumber": "2.number" }
        }))
        .expect("deserialize future type request");
        assert_eq!(
            future_type.cipher.validate_for_personal_vault("user-1"),
            Ok(())
        );

        let attachment_rotation: CipherRequestFlat = serde_json::from_value(json!({
            "type": 1,
            "name": "2.name",
            "login": {},
            "attachments2": { "attachment-1": { "key": "2.key" } }
        }))
        .expect("deserialize attachment rotation request");
        assert!(
            attachment_rotation
                .cipher
                .validate_for_personal_vault("user-1")
                .is_ok()
        );
    }

    #[test]
    fn invalid_ssh_key_is_returned_as_null_for_mobile_decoder_safety() {
        let value = serde_json::to_value(Cipher {
            id: "ssh-invalid".to_string(),
            user_id: Some("user-1".to_string()),
            organization_id: None,
            r#type: 5,
            data: json!({
                "name": "2.name",
                "sshKey": { "publicKey": "2.public" }
            }),
            key: None,
            favorite: false,
            folder_id: None,
            deleted_at: None,
            archived_at: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
            object: "cipherDetails".to_string(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        })
        .expect("serialize invalid SSH cipher");

        assert_eq!(value.get("sshKey"), Some(&Value::Null));
    }

    #[test]
    fn cipher_serialization_normalizes_strict_android_fields() {
        let cipher = Cipher {
            id: "test-id".to_string(),
            user_id: Some("user-1".to_string()),
            organization_id: None,
            r#type: 1,
            data: json!({
                "name": "2.name",
                "login": {
                    "username": "2.user",
                    "password": "2.password",
                    "passwordRevisionDate": "not-a-date",
                    "uris": [
                        { "uri": "2.uri", "match": "1" },
                        { "uri": "2.uri-2", "match": "invalid" }
                    ]
                },
                "fields": [
                    { "name": "2.field", "value": "2.value", "type": "0" },
                    { "name": "2.hidden", "value": "2.secret", "type": null },
                    "invalid"
                ],
                "passwordHistory": [
                    { "password": "2.old", "lastUsedDate": "not-a-date" },
                    { "password": null, "lastUsedDate": "2026-01-01T00:00:00Z" }
                ]
            }),
            key: None,
            favorite: false,
            folder_id: None,
            deleted_at: None,
            archived_at: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
            object: "cipherDetails".to_string(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        };

        let value = serde_json::to_value(cipher).expect("serialize cipher");

        assert_eq!(value.pointer("/fields/0/type"), Some(&json!(0)));
        assert_eq!(value.pointer("/fields/1/type"), Some(&json!(1)));
        assert_eq!(value.pointer("/fields/2"), None);
        assert_eq!(
            value.pointer("/passwordHistory/0/password"),
            Some(&json!("2.old"))
        );
        assert_eq!(value.pointer("/passwordHistory/1"), None);
        assert_eq!(
            value.pointer("/passwordHistory/0/lastUsedDate"),
            Some(&json!("1970-01-01T00:00:00.000000Z"))
        );
        assert_eq!(value.pointer("/login/uris/0/match"), Some(&json!(1)));
        assert_eq!(value.pointer("/login/uris/1/match"), Some(&Value::Null));
        assert_eq!(
            value.pointer("/login/passwordRevisionDate"),
            Some(&json!("1970-01-01T00:00:00.000000Z"))
        );
    }

    #[test]
    fn cipher_dates_are_normalized_and_stale_updates_are_detected() {
        assert_eq!(
            normalize_optional_rfc3339(Some("2026-01-01T08:00:00+08:00")),
            Some("2026-01-01T08:00:00.000000+08:00".to_string())
        );
        assert_eq!(normalize_optional_rfc3339(Some("invalid")), None);
        assert!(client_revision_is_stale(
            "2026-01-01T00:00:03.000Z",
            Some("2026-01-01T00:00:00.000Z")
        ));
        assert!(!client_revision_is_stale(
            "2026-01-01T00:00:01.500Z",
            Some("2026-01-01T00:00:00.000Z")
        ));
        assert!(!client_revision_is_stale(
            "2026-01-01T00:00:03.000Z",
            Some("invalid")
        ));
    }

    #[test]
    fn create_cipher_request_deserializes_pascalcase_compat() {
        let body = json!({
            "Cipher": { "type": 1, "name": "n" },
            "CollectionIds": ["c1"]
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.r#type, 1);
        assert_eq!(req.cipher.name, "n");
        assert_eq!(req.collection_ids, vec!["c1".to_string()]);
    }

    #[test]
    fn create_cipher_request_treats_empty_folder_id_as_none() {
        let body = json!({
            "cipher": { "type": 1, "name": "n", "folderId": "" },
            "collectionIds": []
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.folder_id, None);
    }

    #[test]
    fn create_cipher_request_deserializes_archived_date() {
        let body = json!({
            "cipher": {
                "type": 1,
                "name": "n",
                "archivedDate": "2026-05-06T00:00:00.000Z"
            },
            "collectionIds": []
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(
            req.cipher.archived_date,
            Some("2026-05-06T00:00:00.000Z".to_string())
        );
    }
}

// Represents the "Cipher" object within the incoming request payload.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestData {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments2: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_account: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drivers_license: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_for: Option<String>,
}

impl CipherRequestData {
    pub fn validate_for_personal_vault(&self, user_id: &str) -> Result<(), &'static str> {
        if self.organization_id.is_some() {
            return Err("Organization ciphers are not supported by this personal vault");
        }
        self.validate_for_vault(user_id)
    }

    pub fn validate_for_vault(&self, user_id: &str) -> Result<(), &'static str> {
        if self
            .encrypted_for
            .as_deref()
            .is_some_and(|encrypted_for| encrypted_for != user_id)
        {
            return Err("Cipher is encrypted for a different user");
        }
        if self
            .attachments2
            .as_ref()
            .is_some_and(|attachments| !attachments.is_object())
        {
            return Err("Invalid cipher attachment key rotation data");
        }
        let type_data = match self.r#type {
            1 => self.login.as_ref(),
            2 => self.secure_note.as_ref(),
            3 => self.card.as_ref(),
            4 => self.identity.as_ref(),
            5 => self.ssh_key.as_ref(),
            6 => self.bank_account.as_ref(),
            7 => self.drivers_license.as_ref(),
            8 => self.passport.as_ref(),
            _ => return Err("Invalid cipher type"),
        };

        let Some(type_data) = type_data.filter(|value| value.is_object()) else {
            return Err("Cipher type data is missing");
        };

        if self.r#type == 5 {
            let mut ssh_key = type_data.clone();
            normalize_ssh_key(&mut ssh_key);
            if ssh_key.is_null() {
                return Err("SSH key is missing required encrypted fields");
            }
        }

        Ok(())
    }
}

// Represents the full request payload for creating a cipher.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherRequest {
    #[serde(alias = "Cipher")]
    pub cipher: CipherRequestData,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestFlat {
    #[serde(flatten)]
    pub cipher: CipherRequestData,
    #[serde(default)]
    pub collection_ids: Vec<String>,
}

use serde::Deserialize;

pub type ImportCipher = super::cipher::CipherRequestData;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportFolder {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    pub key: usize,
    pub value: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<ImportCipher>,
    pub folders: Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}

#[cfg(test)]
mod tests {
    use super::ImportCipher;
    use serde_json::json;

    #[test]
    fn import_cipher_allows_missing_folder_id() {
        let body = json!({
            "type": 1,
            "organizationId": null,
            "key": "2.cipher-key",
            "name": "n",
            "notes": null,
            "favorite": false,
            "login": { "username": "2.user", "password": "2.password", "uris": [] },
            "card": null,
            "identity": null,
            "secureNote": null,
            "fields": null,
            "passwordHistory": null,
            "reprompt": null,
            "lastKnownRevisionDate": null,
            "archivedDate": null,
            "encryptedFor": "user-1"
        });

        let cipher: ImportCipher = serde_json::from_value(body).expect("deserialize");
        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.key.as_deref(), Some("2.cipher-key"));
        cipher
            .validate_for_personal_vault("user-1")
            .expect("valid import cipher");
    }
}

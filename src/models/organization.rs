use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MEMBER_STATUS_INVITED: i32 = 0;
pub const MEMBER_STATUS_ACCEPTED: i32 = 1;
pub const MEMBER_STATUS_CONFIRMED: i32 = 2;

pub const MEMBER_TYPE_OWNER: i32 = 0;
pub const MEMBER_TYPE_ADMIN: i32 = 1;
pub const MEMBER_TYPE_USER: i32 = 2;
pub const MEMBER_TYPE_MANAGER: i32 = 3;

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Organization {
    pub fn to_json(&self, events_enabled: bool, groups_enabled: bool) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "seats": null,
            "maxCollections": null,
            "maxStorageGb": i16::MAX,
            "use2fa": true,
            "useCustomPermissions": true,
            "useDirectory": false,
            "useEvents": events_enabled,
            "useGroups": groups_enabled,
            "useTotp": true,
            "usePolicies": true,
            "useScim": false,
            "useSso": false,
            "useKeyConnector": false,
            "usePasswordManager": true,
            "useSecretsManager": false,
            "selfHost": true,
            "useApi": true,
            "useDisableSMAdsForUsers": true,
            "useInviteLinks": false,
            "useMyItems": false,
            "useOrganizationDomains": false,
            "usePam": false,
            "usePhishingBlocker": false,
            "hasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "useResetPassword": true,
            "allowAdminAccessToAllCollectionItems": true,
            "limitCollectionCreation": true,
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,
            "businessName": self.name,
            "businessAddress1": null,
            "businessAddress2": null,
            "businessAddress3": null,
            "businessCountry": null,
            "businessTaxNumber": null,
            "maxAutoscaleSeats": null,
            "maxAutoscaleSmSeats": null,
            "maxAutoscaleSmServiceAccounts": null,
            "secretsManagerPlan": null,
            "smSeats": null,
            "smServiceAccounts": null,
            "billingEmail": self.billing_email,
            "planType": 6,
            "usersGetPremium": true,
            "object": "organization"
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Membership {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub invited_by_email: Option<String>,
    pub access_all: i32,
    pub key: String,
    pub status: i32,
    #[serde(rename = "type")]
    pub member_type: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
    pub permissions: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Membership {
    pub fn is_confirmed(&self) -> bool {
        self.status == MEMBER_STATUS_CONFIRMED
    }

    pub fn is_owner(&self) -> bool {
        self.member_type == MEMBER_TYPE_OWNER
    }

    pub fn is_admin(&self) -> bool {
        matches!(self.member_type, MEMBER_TYPE_OWNER | MEMBER_TYPE_ADMIN)
    }

    pub fn has_full_access(&self) -> bool {
        self.is_admin() || self.access_all != 0
    }

    pub fn client_type(&self) -> i32 {
        if self.member_type == MEMBER_TYPE_MANAGER {
            4
        } else {
            self.member_type
        }
    }

    pub fn profile_json(
        &self,
        org: &Organization,
        events_enabled: bool,
        groups_enabled: bool,
    ) -> Value {
        let client_type = self.client_type();
        let custom_full_access = client_type == 4 && self.access_all != 0;
        let permissions: Value = serde_json::from_str(&self.permissions).unwrap_or_else(|_| {
            json!({
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                "createNewCollections": custom_full_access,
                "editAnyCollection": custom_full_access,
                "deleteAnyCollection": custom_full_access,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false,
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false
            })
        });

        json!({
            "id": self.organization_id,
            "identifier": null,
            "name": org.name,
            "seats": 20,
            "maxCollections": null,
            "usersGetPremium": true,
            "use2fa": true,
            "useDirectory": false,
            "useEvents": events_enabled,
            "useGroups": groups_enabled,
            "useTotp": true,
            "useScim": false,
            "usePolicies": true,
            "useApi": true,
            "selfHost": true,
            "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "useResetPassword": true,
            "ssoBound": false,
            "useSso": false,
            "useKeyConnector": false,
            "useSecretsManager": false,
            "usePasswordManager": true,
            "useCustomPermissions": true,
            "useActivateAutofillPolicy": false,
            "useAdminSponsoredFamilies": false,
            "useRiskInsights": false,
            "useDisableSMAdsForUsers": true,
            "useInviteLinks": false,
            "useMyItems": false,
            "useOrganizationDomains": false,
            "usePam": false,
            "usePhishingBlocker": false,
            "organizationUserId": self.id,
            "providerId": null,
            "providerName": null,
            "providerType": null,
            "familySponsorshipFriendlyName": null,
            "familySponsorshipAvailable": false,
            "productTierType": 3,
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "familySponsorshipLastSyncDate": null,
            "familySponsorshipValidUntil": null,
            "familySponsorshipToDelete": null,
            "accessSecretsManager": false,
            "limitCollectionCreation": self.member_type < MEMBER_TYPE_MANAGER || self.access_all == 0,
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,
            "allowAdminAccessToAllCollectionItems": true,
            "userIsManagedByOrganization": false,
            "userIsClaimedByOrganization": false,
            "permissions": permissions,
            "maxStorageGb": i16::MAX,
            "userId": self.user_id,
            "key": self.key,
            "status": self.status,
            "type": client_type,
            "enabled": self.status >= MEMBER_STATUS_INVITED,
            "object": "profileOrganization"
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub member_id: String,
    pub invited_by_email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_membership(member_type: i32) -> Membership {
        Membership {
            id: "membership".to_string(),
            user_id: "user".to_string(),
            organization_id: "org".to_string(),
            invited_by_email: None,
            access_all: 1,
            key: "key".to_string(),
            status: MEMBER_STATUS_CONFIRMED,
            member_type,
            reset_password_key: None,
            external_id: None,
            permissions: "{}".to_string(),
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        }
    }

    #[test]
    fn role_order_helpers_match_vaultwarden() {
        assert!(sample_membership(MEMBER_TYPE_OWNER).is_admin());
        assert!(sample_membership(MEMBER_TYPE_ADMIN).is_admin());
        assert!(!sample_membership(MEMBER_TYPE_MANAGER).is_admin());
        assert_eq!(sample_membership(MEMBER_TYPE_MANAGER).client_type(), 4);
    }

    #[test]
    fn profile_organization_has_client_contract_fields() {
        let membership = sample_membership(MEMBER_TYPE_OWNER);
        let org = Organization {
            id: "org".to_string(),
            name: "Team".to_string(),
            billing_email: "owner@example.com".to_string(),
            private_key: None,
            public_key: None,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        };
        let value = membership.profile_json(&org, false, false);
        assert_eq!(value["organizationUserId"], "membership");
        assert_eq!(value["object"], "profileOrganization");
        assert_eq!(value["type"], MEMBER_TYPE_OWNER);
    }
}

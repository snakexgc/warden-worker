use axum::extract::DefaultBodyLimit;
use axum::{
    Router,
    extract::State as AxumState,
    response::Html,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use worker::{Context, Env};

use super::{
    core::{
        accounts, attachments, ciphers, compat, config, devices, events, folders, hibp, import,
        organizations, sends, settings, sync, two_factor, usage, webauthn,
    },
    icons, identity, web as css,
};
use crate::worker_runtime::background::BackgroundExecutor;
use crate::worker_runtime::jwt_manager::JwtKeys;
use crate::worker_runtime::r2_file::REQUEST_BODY_LIMIT_BYTES;
use crate::worker_runtime::two_factor_key_manager::TwoFactorKey;

pub struct AppState {
    pub env: Env,
    pub ctx: BackgroundExecutor,
    pub jwt_keys: Arc<JwtKeys>,
    pub two_factor_key: Arc<TwoFactorKey>,
}

impl AppState {
    pub fn public_url(&self, path: &str) -> String {
        let base = self.env.secret("DOMAIN").ok().and_then(|secret| {
            secret
                .as_ref()
                .as_string()
                .filter(|value| !value.trim().is_empty())
        });
        match base {
            Some(base) => format!("{}{}", base.trim_end_matches('/'), path),
            None => path.to_string(),
        }
    }
}

async fn demo_html(AxumState(_state): AxumState<Arc<AppState>>) -> Html<&'static str> {
    Html(include_str!("../../static/demo.html"))
}

pub fn api_router_with_keys(
    env: Env,
    ctx: Option<Context>,
    jwt_keys: JwtKeys,
    two_factor_key: TwoFactorKey,
) -> Router<()> {
    let app_state = Arc::new(AppState {
        env,
        ctx: match ctx {
            Some(context) => BackgroundExecutor::from_context(context),
            None => BackgroundExecutor::detached(),
        },
        jwt_keys: Arc::new(jwt_keys),
        two_factor_key: Arc::new(two_factor_key),
    });

    Router::new()
        .route("/demo.html", get(demo_html))
        .route(
            "/.well-known/apple-app-site-association",
            get(config::apple_app_site_association),
        )
        .route("/css/vaultwarden.css", get(css::vaultwarden_css))
        .route("/icons/{*path}", get(icons::get_icon))
        // Turnstile send-access verification
        .route("/send-verify", get(sends::send_verify_page))
        .route("/api/send-verify", post(sends::post_send_verify))
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/prelogin/password",
            post(accounts::prelogin),
        )
        .route("/api/accounts/prelogin", post(accounts::prelogin))
        .route("/api/accounts/prelogin/password", post(accounts::prelogin))
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        .route(
            "/identity/accounts/register/verification-email-clicked",
            post(accounts::registration_verification_clicked),
        )
        .route(
            "/api/accounts/profile",
            get(accounts::profile)
                .post(accounts::post_profile)
                .put(accounts::post_profile),
        )
        .route(
            "/api/accounts/avatar",
            put(accounts::put_avatar).post(accounts::put_avatar),
        )
        .route(
            "/api/accounts/security-stamp",
            post(accounts::post_security_stamp),
        )
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/password-hint", post(accounts::password_hint))
        .route("/api/accounts/request-otp", post(accounts::request_otp))
        .route("/accounts/request-otp", post(accounts::request_otp))
        .route("/api/accounts/verify-otp", post(accounts::verify_otp))
        .route("/accounts/verify-otp", post(accounts::verify_otp))
        .route(
            "/api/accounts/verify-password",
            post(accounts::verify_password),
        )
        .route("/accounts/verify-password", post(accounts::verify_password))
        .route("/api/devices", get(devices::get_devices))
        .route(
            "/api/devices/identifier/{id}",
            get(devices::get_device_by_identifier),
        )
        .route("/api/devices/knowndevice", get(devices::knowndevice))
        .route(
            "/api/devices/identifier/{id}/token",
            put(devices::device_token).post(devices::device_token),
        )
        .route(
            "/api/devices/identifier/{id}/clear-token",
            put(devices::clear_device_token).post(devices::clear_device_token),
        )
        .route(
            "/api/auth-requests",
            get(devices::get_auth_requests).post(devices::post_auth_request),
        )
        .route(
            "/api/auth-requests/admin-request",
            post(devices::post_auth_request),
        )
        .route(
            "/api/auth-requests/",
            get(devices::get_auth_requests).post(devices::post_auth_request),
        )
        .route(
            "/api/auth-requests/admin-request/",
            post(devices::post_auth_request),
        )
        .route(
            "/api/auth-requests/pending",
            get(devices::get_auth_requests_pending),
        )
        .route(
            "/api/auth-requests/pending/",
            get(devices::get_auth_requests_pending),
        )
        .route(
            "/api/auth-requests/{id}",
            get(devices::get_auth_request).put(devices::put_auth_request),
        )
        .route(
            "/api/auth-requests/{id}/",
            get(devices::get_auth_request).put(devices::put_auth_request),
        )
        .route(
            "/api/auth-requests/{id}/response",
            get(devices::get_auth_request_response),
        )
        .route(
            "/api/auth-requests/{id}/response/",
            get(devices::get_auth_request_response),
        )
        .route(
            "/api/accounts/password",
            post(accounts::change_master_password),
        )
        .route("/api/accounts/email", post(accounts::change_email))
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::rotate_user_account_keys),
        )
        .route("/api/accounts/tasks", get(accounts::get_tasks))
        .route("/api/tasks", get(accounts::get_tasks))
        .route("/api/accounts/delete", post(accounts::post_delete_account))
        .route("/api/accounts", delete(accounts::delete_account))
        .route(
            "/api/accounts/delete-recover",
            post(accounts::post_delete_recover),
        )
        .route(
            "/api/accounts/delete-recover-token",
            post(accounts::post_delete_recover_token),
        )
        .route("/api/accounts/keys", post(accounts::post_keys))
        .route(
            "/api/users/{user_id}/public-key",
            get(accounts::get_public_key),
        )
        .route("/api/accounts/api-key", post(accounts::post_api_key))
        .route(
            "/api/accounts/rotate-api-key",
            post(accounts::rotate_api_key),
        )
        .route(
            "/api/accounts/verify-email",
            post(accounts::post_verify_email),
        )
        .route(
            "/api/accounts/verify-email-token",
            post(accounts::post_verify_email_token),
        )
        .route(
            "/api/accounts/email-token",
            post(accounts::post_email_token),
        )
        .route(
            "/api/accounts/set-password",
            post(accounts::post_set_password),
        )
        .route("/api/two-factor", get(two_factor::two_factor_status))
        .route(
            "/api/two-factor/get-device-verification-settings",
            get(two_factor::get_device_verification_settings),
        )
        .route(
            "/api/two-factor/get-authenticator",
            post(two_factor::get_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(two_factor::activate_authenticator)
                .put(two_factor::activate_authenticator_put)
                .delete(two_factor::disable_authenticator_vw),
        )
        .route(
            "/api/two-factor/authenticator/request",
            post(two_factor::authenticator_request),
        )
        .route(
            "/api/two-factor/authenticator/enable",
            post(two_factor::authenticator_enable),
        )
        .route(
            "/api/two-factor/authenticator/disable",
            post(two_factor::authenticator_disable),
        )
        .route("/api/two-factor/get-email", post(two_factor::get_email))
        .route(
            "/api/two-factor/get-webauthn",
            post(webauthn::two_factor_get_webauthn),
        )
        .route(
            "/api/two-factor/get-webauthn-challenge",
            post(webauthn::two_factor_get_webauthn_challenge),
        )
        .route(
            "/api/two-factor/webauthn",
            post(webauthn::two_factor_put_webauthn)
                .put(webauthn::two_factor_put_webauthn)
                .delete(webauthn::two_factor_delete_webauthn),
        )
        .route("/api/two-factor/send-email", post(two_factor::send_email))
        .route(
            "/api/two-factor/email",
            put(two_factor::verify_email).delete(two_factor::disable_email),
        )
        .route(
            "/api/two-factor/disable",
            post(two_factor::disable_twofactor).put(two_factor::disable_twofactor_put),
        )
        .route("/api/two-factor/get-recover", post(two_factor::get_recover))
        .route("/api/two-factor/recover", post(two_factor::recover))
        .route(
            "/two-factor/send-email-login",
            post(two_factor::send_email_login),
        )
        .route(
            "/api/two-factor/send-email-login",
            post(two_factor::send_email_login),
        )
        .route("/api/sends", get(sends::get_sends).post(sends::post_send))
        .route(
            "/api/sends/file",
            post(sends::post_send_file_legacy)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route("/api/sends/file/v2", post(sends::post_send_file_v2))
        .route("/api/sends/access", post(sends::post_access))
        .route(
            "/api/sends/access/{access_id}",
            post(sends::post_access_legacy),
        )
        .route(
            "/api/sends/access/file/{file_id}",
            post(sends::post_access_file),
        )
        .route(
            "/api/sends/{send_id}",
            get(sends::get_send)
                .put(sends::put_send)
                .delete(sends::delete_send),
        )
        .route(
            "/api/sends/{send_id}/remove-password",
            put(sends::put_remove_send_password),
        )
        .route(
            "/api/sends/{send_id}/access/file/{file_id}",
            post(sends::post_access_file_legacy),
        )
        .route("/api/sends/{send_id}/{file_id}", get(sends::download_send))
        .route(
            "/api/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route(
            "/sends/{send_id}/file/{file_id}",
            post(sends::post_send_file_v2_data)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route("/api/collections", get(organizations::get_collections))
        .route("/api/policies", get(compat::get_policies))
        .route(
            "/api/organizations",
            get(organizations::get_organizations).post(organizations::create_organization),
        )
        .route(
            "/api/organizations/{org_id}",
            get(organizations::get_organization)
                .post(organizations::update_organization)
                .put(organizations::update_organization)
                .delete(organizations::delete_organization),
        )
        .route(
            "/api/organizations/{org_id}/delete",
            post(organizations::delete_organization),
        )
        .route(
            "/api/organizations/{org_id}/leave",
            post(organizations::leave_organization),
        )
        .route(
            "/api/organizations/{org_id}/keys",
            get(organizations::get_organization_public_key)
                .post(organizations::set_organization_keys),
        )
        .route(
            "/api/organizations/{org_id}/public-key",
            get(organizations::get_organization_public_key),
        )
        .route(
            "/api/organizations/{identifier}/auto-enroll-status",
            get(organizations::get_auto_enroll_status),
        )
        .route(
            "/api/organizations/{org_id}/billing/metadata",
            get(organizations::get_billing_metadata),
        )
        .route(
            "/api/organizations/{org_id}/billing/vnext/warnings",
            get(organizations::get_billing_warnings),
        )
        .route(
            "/api/organizations/{org_id}/billing/vnext/self-host/metadata",
            get(organizations::get_self_host_billing_metadata),
        )
        .route(
            "/api/organizations/{org_id}/export",
            get(organizations::export_organization),
        )
        .route(
            "/api/organizations/{org_id}/collections",
            get(organizations::get_org_collections)
                .post(organizations::create_collection)
                .delete(organizations::bulk_delete_collections),
        )
        .route(
            "/api/organizations/{org_id}/collections/details",
            get(organizations::get_org_collections_details),
        )
        .route(
            "/api/organizations/{org_id}/collections/bulk-access",
            post(organizations::bulk_access_collections),
        )
        .route(
            "/api/organizations/{org_id}/collections/{collection_id}",
            get(organizations::get_org_collection)
                .post(organizations::update_collection)
                .put(organizations::update_collection)
                .delete(organizations::delete_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{collection_id}/delete",
            post(organizations::delete_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{collection_id}/details",
            get(organizations::get_org_collection_details),
        )
        .route(
            "/api/organizations/{org_id}/collections/{collection_id}/users",
            get(organizations::get_collection_users),
        )
        .route(
            "/api/organizations/{org_id}/policies",
            get(organizations::list_policies),
        )
        .route(
            "/api/organizations/{org_id}/policies/master-password",
            get(organizations::get_master_password_policy),
        )
        .route(
            "/api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password",
            get(organizations::get_sso_placeholder_master_password_policy),
        )
        .route(
            "/api/organizations/{org_id}/policies/token",
            get(organizations::list_policies_by_invite_token),
        )
        .route(
            "/api/organizations/{org_id}/policies/{policy_type}",
            get(organizations::get_policy).put(organizations::put_policy),
        )
        .route(
            "/api/organizations/{org_id}/policies/{policy_type}/vnext",
            put(organizations::put_policy),
        )
        .route(
            "/api/organizations/{org_id}/groups",
            get(organizations::get_groups)
                .post(organizations::create_group)
                .delete(organizations::bulk_delete_groups),
        )
        .route(
            "/api/organizations/{org_id}/groups/details",
            get(organizations::get_groups_details),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}",
            get(organizations::get_group)
                .post(organizations::update_group)
                .put(organizations::update_group)
                .delete(organizations::delete_group),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/details",
            get(organizations::get_group_details),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/delete",
            post(organizations::delete_group),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/users",
            get(organizations::get_group_members).put(organizations::put_group_members),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/delete-user/{member_id}",
            post(organizations::delete_group_member),
        )
        .route(
            "/api/organizations/{org_id}/users",
            get(organizations::get_members).delete(organizations::bulk_delete_members),
        )
        .route(
            "/api/organizations/{org_id}/users/mini-details",
            get(organizations::get_member_mini_details),
        )
        .route(
            "/api/organizations/{org_id}/users/public-keys",
            post(organizations::member_public_keys),
        )
        .route(
            "/api/organizations/{org_id}/users/invite",
            post(organizations::invite_members),
        )
        .route(
            "/api/organizations/{org_id}/users/reinvite",
            post(organizations::bulk_reinvite_members),
        )
        .route(
            "/api/organizations/{org_id}/users/confirm",
            post(organizations::bulk_confirm_invites),
        )
        .route(
            "/api/organizations/{org_id}/users/revoke",
            put(organizations::bulk_revoke_members),
        )
        .route(
            "/api/organizations/{org_id}/users/restore",
            put(organizations::bulk_restore_members),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}",
            get(organizations::get_member)
                .post(organizations::edit_member)
                .put(organizations::edit_member)
                .delete(organizations::delete_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/accept",
            post(organizations::accept_invite),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/confirm",
            post(organizations::confirm_invite),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reinvite",
            post(organizations::reinvite_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/revoke",
            post(organizations::revoke_member).put(organizations::revoke_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore",
            post(organizations::restore_member).put(organizations::restore_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore/vnext",
            put(organizations::restore_member),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/recover-account",
            put(organizations::recover_account),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password",
            put(organizations::reset_member_password),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-details",
            get(organizations::get_reset_password_details),
        )
        .route(
            "/api/organizations/{org_id}/users/{user_id}/reset-password-enrollment",
            put(organizations::update_reset_password_enrollment),
        )
        .route(
            "/api/organizations/{org_id}/events",
            get(events::get_organization_events),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/events",
            get(events::get_member_events),
        )
        // Main data sync route
        .route("/api/sync", get(sync::sync))
        // Ciphers CRUD
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/purge", post(ciphers::purge_personal_vault))
        .route(
            "/api/ciphers/{cipher_id}/attachment/v2",
            post(attachments::create_attachment_v2),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment",
            post(attachments::create_attachment_legacy)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}",
            get(attachments::attachment_metadata)
                .post(attachments::upload_attachment_v2)
                .delete(attachments::delete_attachment)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/delete",
            post(attachments::delete_attachment_post),
        )
        .route(
            "/ciphers/{cipher_id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_v2)
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        .route(
            "/attachments/{cipher_id}/{attachment_id}",
            get(attachments::download_attachment),
        )
        .route(
            "/api/ciphers",
            get(ciphers::get_ciphers)
                .post(ciphers::post_ciphers)
                .delete(ciphers::hard_delete_ciphers_delete),
        )
        .route("/api/ciphers/import", post(import::import_data))
        .route(
            "/api/ciphers/import-organization",
            post(import::import_organization),
        )
        .route(
            "/api/ciphers/organization-details",
            get(ciphers::get_organization_ciphers),
        )
        .route(
            "/api/ciphers/bulk-collections",
            post(ciphers::bulk_update_collections),
        )
        .route(
            "/api/ciphers/move",
            post(ciphers::move_ciphers).put(ciphers::move_ciphers_put),
        )
        .route(
            "/api/ciphers/{id}",
            get(ciphers::get_cipher)
                .post(ciphers::post_cipher)
                .put(ciphers::update_cipher)
                .delete(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/details",
            get(ciphers::get_cipher_details),
        )
        .route("/api/ciphers/{id}/events", get(events::get_cipher_events))
        .route(
            "/api/ciphers/{id}/collections",
            post(ciphers::update_cipher_collections).put(ciphers::update_cipher_collections),
        )
        .route(
            "/api/ciphers/{id}/collections_v2",
            post(ciphers::update_cipher_collections_v2).put(ciphers::update_cipher_collections_v2),
        )
        .route(
            "/api/ciphers/{id}/collections-admin",
            post(ciphers::update_cipher_collections_admin)
                .put(ciphers::update_cipher_collections_admin),
        )
        .route(
            "/api/ciphers/{id}/partial",
            post(ciphers::post_cipher_partial).put(ciphers::put_cipher_partial),
        )
        .route(
            "/api/ciphers/{id}/delete",
            put(ciphers::soft_delete_cipher).post(ciphers::hard_delete_cipher_post),
        )
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        .route("/api/ciphers/{id}/archive", put(ciphers::archive_cipher))
        .route(
            "/api/ciphers/{id}/unarchive",
            put(ciphers::unarchive_cipher),
        )
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers).post(ciphers::hard_delete_ciphers),
        )
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers))
        .route("/api/ciphers/archive", put(ciphers::archive_ciphers))
        .route("/api/ciphers/unarchive", put(ciphers::unarchive_ciphers))
        // Folders CRUD
        .route(
            "/api/folders",
            get(folders::get_folders).post(folders::create_folder),
        )
        .route(
            "/api/folders/{id}",
            get(folders::get_folder)
                .post(folders::post_folder)
                .put(folders::update_folder)
                .delete(folders::delete_folder),
        )
        .route(
            "/api/folders/{id}/delete",
            post(folders::delete_folder_post),
        )
        .route(
            "/api/settings/domains",
            get(settings::get_domains)
                .post(settings::post_domains)
                .put(settings::put_domains),
        )
        .route("/api/config", get(config::config))
        .route("/api/plans", get(organizations::get_plans))
        .route("/alive", get(config::alive).head(config::alive_head))
        .route("/api/alive", get(config::alive).head(config::alive_head))
        .route("/api/now", get(config::now))
        .route("/api/version", get(config::version))
        .route("/api/hibp/breach", get(hibp::hibp_breach))
        .route("/events/collect", post(events::post_events_collect))
        .route(
            "/accounts/webauthn/assertion-options",
            get(webauthn::identity_assertion_options).post(webauthn::identity_assertion_options),
        )
        .route(
            "/identity/accounts/webauthn/assertion-options",
            get(webauthn::identity_assertion_options).post(webauthn::identity_assertion_options),
        )
        .route(
            "/api/webauthn",
            get(webauthn::list_credentials).post(webauthn::create_credential),
        )
        .route(
            "/api/webauthn/attestation-options",
            post(webauthn::attestation_options),
        )
        .route(
            "/api/webauthn/prf-probe",
            post(webauthn::webauthn_prf_probe),
        )
        .route(
            "/api/webauthn/assertion-options",
            post(webauthn::assertion_options),
        )
        .route(
            "/api/webauthn/{credential_id}",
            put(webauthn::update_credential),
        )
        .route(
            "/api/webauthn/{credential_id}/delete",
            post(webauthn::delete_credential),
        )
        .route("/api/d1/usage", get(usage::d1_usage))
        .with_state(app_state)
}

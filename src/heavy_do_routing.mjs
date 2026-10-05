const PERSONAL_VAULT_HEAVY_DO_NAME = "personal-vault";

// These routes create or verify the Vaultwarden-compatible server password
// verifier (PBKDF2-HMAC-SHA256, 600,000 iterations). They must execute inside
// HeavyDo so the Free-plan entry Worker only performs lightweight routing.
const PASSWORD_HEAVY_DO_PATHS = new Set([
  "/identity/accounts/register/finish",
  "/identity/connect/token",
  "/api/accounts/password",
  "/api/accounts/email",
  "/api/accounts/kdf",
  "/api/accounts/verify-password",
  "/accounts/verify-password",
  "/api/accounts/delete",
  "/api/accounts",
  "/api/accounts/set-password",
  "/api/accounts/key-management/rotate-user-account-keys",
]);

const HEAVY_DO_PREFIXES = [
  "/api/config",
  "/api/sync",
  "/identity/accounts/prelogin",
  "/api/accounts/prelogin",
  "/identity/accounts/webauthn/assertion-options",
  "/accounts/webauthn/assertion-options",
  // Two-factor and WebAuthn handlers can verify the master password.
  "/api/two-factor",
  "/api/webauthn",
  "/notifications",
  "/icons",
  "/api/auth-requests",
  "/api/devices/knowndevice",
  "/two-factor/send-email-login",
  "/api/ciphers",
  "/api/folders",
];

export function normalizePathname(pathname) {
  if (typeof pathname !== "string" || pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

export function shouldOffloadToHeavyDo(pathname) {
  if (PASSWORD_HEAVY_DO_PATHS.has(pathname)) return true;

  for (const prefix of HEAVY_DO_PREFIXES) {
    if (pathname === prefix || pathname.startsWith(prefix + "/")) {
      return true;
    }
  }
  return false;
}

export function getHeavyDoName() {
  // This is a personal, single-user vault. HeavyDo does not own business state;
  // it only supplies a larger CPU budget for selected routes, so one fixed
  // instance is sufficient and avoids creating per-user or per-request objects.
  return PERSONAL_VAULT_HEAVY_DO_NAME;
}

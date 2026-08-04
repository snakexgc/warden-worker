const HEAVY_DO_PREFIX = "vault";

// These routes create or verify the Vaultwarden-compatible server password
// verifier (PBKDF2-HMAC-SHA256, 600,000 iterations). They must execute inside
// HeavyDo so the Free-plan entry Worker only performs lightweight routing.
const PASSWORD_HEAVY_DO_PATHS = new Set([
  "/identity/accounts/register",
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
  "/api/organizations",
  "/api/collections",
  "/api/policies",
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

function decodeJwtSubject(value) {
  try {
    const token = value?.replace(/^Bearer\s+/i, "");
    const payload = token?.split(".")[1];
    if (!payload) return null;
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const json = JSON.parse(atob(padded));
    return typeof json.sub === "string" && json.sub ? json.sub : null;
  } catch {
    return null;
  }
}

async function requestIdentity(request) {
  if (!(request instanceof Request)) return "anonymous";
  const url = new URL(request.url);
  const orgMatch = url.pathname.match(/^\/api\/organizations\/([^/]+)/);
  if (orgMatch) return `org:${orgMatch[1]}`;

  const subject = decodeJwtSubject(request.headers.get("authorization"));
  if (subject) return `user:${subject}`;

  try {
    const clone = request.clone();
    const contentType = clone.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const body = await clone.json();
      const email = body.email || body.username;
      if (typeof email === "string" && email.trim()) {
        return `email:${email.trim().toLowerCase()}`;
      }
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const body = new URLSearchParams(await clone.text());
      const email = body.get("username") || body.get("email");
      if (email?.trim()) return `email:${email.trim().toLowerCase()}`;
    }
  } catch {
    // Falling back to an edge address still avoids the former global object.
  }

  const edgeAddress = request.headers.get("cf-connecting-ip") || "anonymous";
  return `edge:${edgeAddress}`;
}

export async function getHeavyDoName(request) {
  // Names contain only a stable hash; email addresses and user identifiers are
  // never exposed in Durable Object names or platform logs.
  const identity = await requestIdentity(request);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(identity),
  );
  const shard = Array.from(new Uint8Array(digest).slice(0, 12), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return `${HEAVY_DO_PREFIX}-${shard}`;
}

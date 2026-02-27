/**
 * JS wrapper entry point.
 *
 * Route selected hot-path APIs to HEAVY_DO to avoid Worker CPU timeout,
 * while keeping the rest of requests on the Rust WASM worker.
 */

import RustWorker from "../build/index.js";

function normalizePathname(pathname) {
  if (typeof pathname !== "string") return "/";
  if (pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

const HEAVY_DO_PREFIXES = [
  "/api/config",
  "/api/sync",
  "/identity/accounts/prelogin",
  "/api/accounts/prelogin",
  "/identity/accounts/webauthn/assertion-options",
  "/accounts/webauthn/assertion-options",
  "/api/two-factor",
  "/api/webauthn",
  "/notifications",
  "/icons",
  "/api/auth-requests",
  "/identity/connect/token",
  "/api/devices/knowndevice",
  "/two-factor/send-email-login",
  "/api/ciphers",
  "/api/folders",
];

function shouldOffloadToHeavyDo(pathname) {
  for (const prefix of HEAVY_DO_PREFIXES) {
    if (pathname === prefix || pathname.startsWith(prefix + "/")) {
      return true;
    }
  }
  return false;
}

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!auth) return null;
  const m = auth.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : null;
}

function decodeJwtSubUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const pad = parts[1].length % 4;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/") + (pad ? "=".repeat(4 - pad) : "");
    const json = atob(b64);
    return JSON.parse(json)?.sub ?? null;
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);

    if (env.HEAVY_DO && shouldOffloadToHeavyDo(url.pathname)) {
      const token = getBearerToken(request);
      const sub = token ? decodeJwtSubUnsafe(token) : null;
      const name = computeRequestShard(url, sub);
      const id = env.HEAVY_DO.idFromName(name);
      const stub = env.HEAVY_DO.get(id);
      return stub.fetch(request);
    }

    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

function computeRequestShard(url, tokenSub) {
  if (tokenSub) {
    return `user:${tokenSub}`;
  }

  if (url.pathname === "/icons" || url.pathname.startsWith("/icons/")) {
    const host = (url.searchParams.get("hostname") || url.searchParams.get("domain") || "default").toLowerCase();
    const bucket = host.charCodeAt(0) % 16;
    return `icons-bucket:${bucket}`;
  }

  if (url.pathname === "/api/auth-requests" || url.pathname.startsWith("/api/auth-requests/")) {
    const idSeed = `${url.pathname}|${url.searchParams.get("code") || ""}`;
    const bucket = idSeed.charCodeAt(0) % 16;
    return `auth-requests-bucket:${bucket}`;
  }

  return "user:default";
}

export { NotificationsHub, HeavyDo } from "../build/index.js";

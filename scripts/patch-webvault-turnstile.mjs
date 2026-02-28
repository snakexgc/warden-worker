/**
 * patch-webvault-turnstile.mjs
 *
 * Injects a small inline <script> into `static/web-vault/index.html` that
 * intercepts Send-access navigation and redirects to `/send-verify` when the
 * user has not yet completed the Turnstile challenge (no `cf_send_pass_ok` cookie).
 *
 * The guard only activates for `#/send/` routes (anonymous send access).
 * Logged-in users operating on their own sends are unaffected because those
 * routes use `#/sends/` (plural) with auth headers.
 *
 * Run as part of the build:
 *   node ./scripts/patch-webvault-turnstile.mjs
 */

import fs from "node:fs";
import path from "node:path";

// Bump this when the guard script changes to force re-patching.
const GUARD_VERSION = 2;
const MARKER_PREFIX = "/* turnstile-send-guard";
const MARKER = `/* turnstile-send-guard-v${GUARD_VERSION} */`;

const indexPath = path.resolve("static", "web-vault", "index.html");
if (!fs.existsSync(indexPath)) {
  console.error(`[patch-webvault-turnstile] File not found: ${indexPath}`);
  process.exit(1);
}

let html = fs.readFileSync(indexPath, "utf8");

// Check if current version is already applied.
if (html.includes(MARKER)) {
  console.log("[patch-webvault-turnstile] Already patched (v" + GUARD_VERSION + "). No changes needed.");
  process.exit(0);
}

// Remove any previous version of the guard script block.
// The block is: <script>/* turnstile-send-guard... */...guard code...</script>
const oldGuardRegex = /<script>\/\* turnstile-send-guard[^]*?<\/script>/;
if (oldGuardRegex.test(html)) {
  html = html.replace(oldGuardRegex, "");
  console.log("[patch-webvault-turnstile] Removed old guard script.");
}

// The inline script to inject.
// It runs before Angular bootstraps and on every hash-change to detect `#/send/`.
const guardScript = `<script>${MARKER}
(function(){
  var COOKIE_NAME = "cf_send_pass_ok";
  function hasCookie(name) {
    return document.cookie.split(";").some(function(c) {
      return c.trim().indexOf(name + "=") === 0;
    });
  }
  function isSendAccessRoute() {
    // Match /#/send/<access_id> — the anonymous send access route.
    // Do NOT match /#/sends/ (plural, logged-in user's own sends).
    return /^#\\/send\\/[^/]+/.test(window.location.hash);
  }
  function guard() {
    if (isSendAccessRoute() && !hasCookie(COOKIE_NAME)) {
      // Redirect to verification page, preserving the original URL to return to.
      var returnUrl = window.location.pathname + window.location.hash;
      window.location.replace("/send-verify?return=" + encodeURIComponent(returnUrl));
    }
  }
  // Check on initial load.
  guard();
  // Check on hash changes (SPA navigation).
  window.addEventListener("hashchange", guard);
})();
</script>`;

// Inject right after the opening <body ...> tag so it runs before any other scripts.
const bodyTagRegex = /(<body[^>]*>)/i;
if (!bodyTagRegex.test(html)) {
  console.error("[patch-webvault-turnstile] Could not find <body> tag in index.html.");
  process.exit(1);
}

html = html.replace(bodyTagRegex, "$1" + guardScript);

fs.writeFileSync(indexPath, html, "utf8");
console.log("[patch-webvault-turnstile] Patched index.html with Turnstile send guard.");

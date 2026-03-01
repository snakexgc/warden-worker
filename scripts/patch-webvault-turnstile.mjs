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

const LOG_PREFIX = "[patch-webvault-turnstile]";
const MAX_SNIPPET_LEN = 260;

function normalizePath(filePath) {
  return path.relative(process.cwd(), filePath).split(path.sep).join("/");
}

function preview(text, maxLen = MAX_SNIPPET_LEN) {
  const oneLine = String(text).replace(/\s+/g, " ").trim();
  if (oneLine.length <= maxLen) {
    return oneLine;
  }
  return `${oneLine.slice(0, maxLen)}...`;
}

function log(message) {
  console.log(`${LOG_PREFIX} ${message}`);
}

function logError(message) {
  console.error(`${LOG_PREFIX} ${message}`);
}

// Bump this when the guard script changes to force re-patching.
const GUARD_VERSION = 2;
const MARKER_PREFIX = "/* turnstile-send-guard";
const MARKER = `/* turnstile-send-guard-v${GUARD_VERSION} */`;

const webVaultDir = path.resolve("static", "web-vault");
if (!fs.existsSync(webVaultDir)) {
  logError(`Directory not found: ${webVaultDir}`);
  process.exit(1);
}

log(`Scanning directory: ${normalizePath(webVaultDir)}`);

function collectFiles(dir, predicate) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath, predicate));
      continue;
    }
    if (predicate(entry.name, fullPath)) {
      results.push(fullPath);
    }
  }
  return results;
}

function detectWebVaultEntryHtml(baseDir) {
  const htmlFiles = collectFiles(baseDir, (name) => name.endsWith(".html"));
  log(`Discovered ${htmlFiles.length} HTML candidate(s).`);
  let best = null;

  for (const file of htmlFiles) {
    const html = fs.readFileSync(file, "utf8");
    let score = 0;
    const reasons = [];
    if (html.includes("<app-root")) {
      score += 3;
      reasons.push("contains <app-root");
    }
    if (/src=["']app\/main\.[^"']+\.js["']/.test(html)) {
      score += 2;
      reasons.push("references app/main.<hash>.js");
    }
    if (html.includes("layout_frontend")) {
      score += 1;
      reasons.push("contains layout_frontend marker");
    }

    log(
      `Candidate ${normalizePath(file)} | score=${score} | matched-keywords=${reasons.length > 0 ? reasons.join("; ") : "none"}`,
    );

    if (score > 0 && (!best || score > best.score)) {
      best = { file, score };
      log(`Current best candidate -> ${normalizePath(file)} (score=${score})`);
    }
  }

  return best?.file ?? null;
}

const entryHtmlPath = detectWebVaultEntryHtml(webVaultDir);
if (!entryHtmlPath) {
  logError("Could not locate web-vault entry HTML by functional signature.");
  process.exit(1);
}

log(`Selected entry HTML: ${normalizePath(entryHtmlPath)}`);

let html = fs.readFileSync(entryHtmlPath, "utf8");
log(`Loaded HTML content length: ${html.length}`);

// Check if current version is already applied.
if (html.includes(MARKER)) {
  const markerIndex = html.indexOf(MARKER);
  const start = Math.max(0, markerIndex - 80);
  const end = Math.min(html.length, markerIndex + MARKER.length + 80);
  log(
    `Already patched (v${GUARD_VERSION}). Marker found at index=${markerIndex} | snippet="${preview(html.slice(start, end))}"`,
  );
  log("No changes needed.");
  process.exit(0);
}

// Remove any previous version of the guard script block.
// The block is: <script>/* turnstile-send-guard... */...guard code...</script>
const oldGuardRegex = /<script>\/\* turnstile-send-guard[^]*?<\/script>/g;
const oldBlocks = [...html.matchAll(oldGuardRegex)];
if (oldBlocks.length > 0) {
  log(`Found ${oldBlocks.length} old guard block(s) to remove.`);
  oldBlocks.forEach((block, idx) => {
    log(
      `  old-block #${idx + 1} at index=${block.index} | snippet="${preview(block[0])}"`,
    );
  });
  const beforeLen = html.length;
  html = html.replace(oldGuardRegex, "");
  log(`Removed old guard script block(s). Length changed: ${beforeLen} -> ${html.length}`);
} else {
  log("No old guard block found.");
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
const bodyMatch = bodyTagRegex.exec(html);
if (!bodyMatch) {
  logError(`Could not find <body> tag in ${path.relative(webVaultDir, entryHtmlPath)}.`);
  process.exit(1);
}

log(
  `Found body tag at index=${bodyMatch.index} | tag="${preview(bodyMatch[1])}"`,
);

const beforeInsertLen = html.length;

html = html.replace(bodyTagRegex, "$1" + guardScript);
log(`Inserted guard script. Length changed: ${beforeInsertLen} -> ${html.length}`);
log(`Inserted marker keyword: ${MARKER}`);

fs.writeFileSync(entryHtmlPath, html, "utf8");
log(`Patched ${path.relative(webVaultDir, entryHtmlPath)} with Turnstile send guard.`);

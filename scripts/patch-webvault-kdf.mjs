import fs from "node:fs";
import path from "node:path";

const LOG_PREFIX = "[patch-webvault-kdf]";
const SNIPPET_RADIUS = 80;
const MAX_SNIPPET_LEN = 240;
const MAX_LOGGED_MATCHES_PER_RULE = 10;

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

function createGlobalRegex(regex) {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

function collectRuleMatches(content, regex) {
  const globalRegex = createGlobalRegex(regex);
  const hits = [];
  let match;
  while ((match = globalRegex.exec(content)) !== null) {
    const start = Math.max(0, match.index - SNIPPET_RADIUS);
    const end = Math.min(content.length, match.index + match[0].length + SNIPPET_RADIUS);
    hits.push({
      index: match.index,
      before: content.slice(start, match.index),
      matched: match[0],
      after: content.slice(match.index + match[0].length, end),
    });
  }
  return hits;
}

const webVaultAppDir = path.resolve("static", "web-vault", "app");
if (!fs.existsSync(webVaultAppDir)) {
  logError(`Directory not found: ${webVaultAppDir}`);
  process.exit(1);
}

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

const targets = collectFiles(webVaultAppDir, (name) => name.endsWith(".js"));

log(`Scanning directory: ${normalizePath(webVaultAppDir)}`);
log(`Discovered ${targets.length} JavaScript bundle candidate(s).`);
for (const file of targets) {
  log(`Candidate file: ${normalizePath(file)}`);
}

if (targets.length === 0) {
  logError("No JavaScript bundles found under static/web-vault/app");
  process.exit(1);
}

const patches = [
  {
    name: "default-kdf-config",
    search: /const ne=new ee\(ee\.ITERATIONS\.defaultValue\);/g,
    replace:
      "const ne=new te(te.ITERATIONS.defaultValue,te.MEMORY.defaultValue,te.PARALLELISM.defaultValue);",
  },
  {
    name: "kdf-form-default",
    search: /kdf:new a\.MJ\(I\.ao\.PBKDF2_SHA256,\[a\.k0\.required\]\)/g,
    replace: "kdf:new a.MJ(I.ao.Argon2id,[a.k0.required])",
  },
  {
    name: "argon2-register-defaults",
    search: /this\.kdfMemory=s\.memory,this\.kdfParallelism=s\.parallelism/g,
    replace: "this.kdfMemory=null!=s.memory?s.memory:64,this.kdfParallelism=null!=s.parallelism?s.parallelism:4",
  },
  {
    name: "register-request-kdf-params",
    search:
      /new zi\(e,t\.newServerMasterKeyHash,t\.newPasswordHint,i,s,t\.kdfConfig\.kdfType,t\.kdfConfig\.iterations\)/g,
    replace:
      "new zi(e,t.newServerMasterKeyHash,t.newPasswordHint,i,s,t.kdfConfig.kdfType,t.kdfConfig.iterations,null!=t.kdfConfig.memory?t.kdfConfig.memory:64,null!=t.kdfConfig.parallelism?t.kdfConfig.parallelism:4)",
  },
];

const functionalSignals = [
  {
    name: "form-default-argon2id",
    search: /kdf:new [^,]+\.MJ\([^,]+\.ao\.Argon2id,\[[^\]]+\.required\]\)/,
  },
  {
    name: "register-default-memory-parallelism",
    search: /kdfMemory=null!=s\.memory\?s\.memory:64,this\.kdfParallelism=null!=s\.parallelism\?s\.parallelism:4/,
  },
  {
    name: "request-carries-kdf-memory-parallelism",
    search: /kdfConfig\.memory|kdfConfig\.parallelism/,
  },
];

function collectSignalHits(files) {
  const hitMap = new Map(functionalSignals.map((signal) => [signal.name, false]));
  const hitFiles = new Map(functionalSignals.map((signal) => [signal.name, []]));
  for (const file of files) {
    const content = fs.readFileSync(file, "utf8");
    const rel = normalizePath(file);
    log(`Signal scan file: ${rel}`);
    for (const signal of functionalSignals) {
      if (signal.search.test(content)) {
        hitMap.set(signal.name, true);
        hitFiles.get(signal.name).push(rel);
        log(
          `Signal hit: ${signal.name} in ${rel} | keyword regex: ${signal.search.source}`,
        );
      }
    }
  }
  return { hitMap, hitFiles };
}

function allSignalsSatisfied(hitMap) {
  for (const signal of functionalSignals) {
    if (!hitMap.get(signal.name)) {
      return false;
    }
  }
  return true;
}

let totalReplacements = 0;
for (const file of targets) {
  let content = fs.readFileSync(file, "utf8");
  let fileReplacements = 0;
  const rel = normalizePath(file);
  log(`Start patch scan: ${rel}`);

  for (const patch of patches) {
    const matches = collectRuleMatches(content, patch.search);
    if (matches.length > 0) {
      log(
        `Rule matched: ${patch.name} in ${rel} | count=${matches.length} | regex=${patch.search.source}`,
      );
      const logCount = Math.min(matches.length, MAX_LOGGED_MATCHES_PER_RULE);
      for (let i = 0; i < logCount; i++) {
        const hit = matches[i];
        log(
          `  [${patch.name} #${i + 1}] index=${hit.index} | before="${preview(hit.before)}" | matched="${preview(hit.matched)}" | after="${preview(hit.after)}"`,
        );
        log(
          `  [${patch.name} #${i + 1}] replacement="${preview(patch.replace)}"`,
        );
      }
      if (matches.length > MAX_LOGGED_MATCHES_PER_RULE) {
        log(
          `  [${patch.name}] additional ${matches.length - MAX_LOGGED_MATCHES_PER_RULE} match(es) omitted from detailed log.`,
        );
      }
    } else {
      log(`Rule miss: ${patch.name} in ${rel} | regex=${patch.search.source}`);
    }

    const before = content;
    content = content.replace(createGlobalRegex(patch.search), patch.replace);
    if (content !== before) {
      fileReplacements++;
      log(`Rule applied: ${patch.name} in ${rel}`);
    }
  }

  if (fileReplacements > 0) {
    fs.writeFileSync(file, content, "utf8");
    totalReplacements += fileReplacements;
    log(`Patched ${rel} (${fileReplacements} rule(s) hit)`);
  } else {
    log(`No changes for file: ${rel}`);
  }
}

if (totalReplacements === 0) {
  const { hitMap, hitFiles } = collectSignalHits(targets);
  for (const signal of functionalSignals) {
    const files = hitFiles.get(signal.name);
    if (files.length > 0) {
      log(`Signal summary: ${signal.name} found in ${files.join(", ")}`);
    } else {
      log(`Signal summary: ${signal.name} NOT found`);
    }
  }

  if (allSignalsSatisfied(hitMap)) {
    log("KDF behavior already present. No changes needed.");
    process.exit(0);
  }

  const missingSignals = functionalSignals
    .filter((signal) => !hitMap.get(signal.name))
    .map((signal) => signal.name)
    .join(", ");

  logError(`No patch rules matched and required KDF behavior is missing: ${missingSignals}`);
  process.exit(1);
}

const { hitMap: signalHitsAfterPatchMap, hitFiles: signalHitsAfterPatchFiles } = collectSignalHits(targets);
for (const signal of functionalSignals) {
  const files = signalHitsAfterPatchFiles.get(signal.name);
  if (files.length > 0) {
    log(`Post-patch signal: ${signal.name} found in ${files.join(", ")}`);
  } else {
    log(`Post-patch signal: ${signal.name} NOT found`);
  }
}

if (!allSignalsSatisfied(signalHitsAfterPatchMap)) {
  const missingSignals = functionalSignals
    .filter((signal) => !signalHitsAfterPatchMap.get(signal.name))
    .map((signal) => signal.name)
    .join(", ");
  logError(`Patch applied but required KDF behavior is still missing: ${missingSignals}`);
  process.exit(1);
}

log(`Done. Total rule hits: ${totalReplacements}`);

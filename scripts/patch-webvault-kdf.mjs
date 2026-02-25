import fs from "node:fs";
import path from "node:path";

const webVaultAppDir = path.resolve("static", "web-vault", "app");
if (!fs.existsSync(webVaultAppDir)) {
  console.error(`[patch-webvault-kdf] Directory not found: ${webVaultAppDir}`);
  process.exit(1);
}

const targets = fs
  .readdirSync(webVaultAppDir)
  .filter((name) => /^main\..*\.js$/.test(name))
  .map((name) => path.join(webVaultAppDir, name));

if (targets.length === 0) {
  console.error("[patch-webvault-kdf] No main.*.js found under static/web-vault/app");
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

let totalReplacements = 0;
let alreadyPatched = false;
for (const file of targets) {
  let content = fs.readFileSync(file, "utf8");
  let fileReplacements = 0;

  if (content.includes("const ne=new te(")) {
    alreadyPatched = true;
  }

  for (const patch of patches) {
    const before = content;
    content = content.replace(patch.search, patch.replace);
    if (content !== before) {
      fileReplacements++;
    }
  }

  if (fileReplacements > 0) {
    fs.writeFileSync(file, content, "utf8");
    totalReplacements += fileReplacements;
    console.log(`[patch-webvault-kdf] Patched ${path.basename(file)} (${fileReplacements} rule hit)`);
  }
}

if (totalReplacements === 0) {
  if (alreadyPatched) {
    console.log("[patch-webvault-kdf] Bundle already patched. No changes needed.");
    process.exit(0);
  }

  console.error("[patch-webvault-kdf] No patch rules matched. Web vault bundle signature may have changed.");
  process.exit(1);
}

console.log(`[patch-webvault-kdf] Done. Total rule hits: ${totalReplacements}`);

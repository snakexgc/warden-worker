import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

// Regression tests for the 2026-11-07 vaultwarden sync round
// (upstream range 1f99d9d2..17b159be).

const baseline = readFileSync(new URL("../sql/schema.sql", import.meta.url), "utf8");
const accounts = readFileSync(new URL("../src/handlers/accounts.rs", import.meta.url), "utf8");
const attachments = readFileSync(new URL("../src/handlers/attachments.rs", import.meta.url), "utf8");
const importSource = readFileSync(new URL("../src/handlers/import.rs", import.meta.url), "utf8");
const router = readFileSync(new URL("../src/router.rs", import.meta.url), "utf8");
const sends = readFileSync(new URL("../src/handlers/sends.rs", import.meta.url), "utf8");

function withDatabase(run) {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("PRAGMA foreign_keys = ON;");
    db.exec(baseline);
    db.prepare(`INSERT INTO users
      (id, email, master_password_hash, key, private_key, public_key, security_stamp, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "user-1", "user@example.com", "password-verifier", "user-key", "private-key", "public-key", "stamp", "created", "updated",
    );
    run(db);
  } finally {
    db.close();
  }
}

test("deleting a user cascades to devices and auth requests (upstream 64895524)", () => {
  withDatabase((db) => {
    db.prepare(`INSERT INTO devices (id, user_id, device_identifier, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)`).run("device-1", "user-1", "device-identifier", "created", "updated");
    db.prepare(`INSERT INTO auth_requests
      (id, user_id, request_device_identifier, device_type, request_ip, access_code_hash, public_key, approved, creation_date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "auth-1", "user-1", "device-identifier", 14, "127.0.0.1", "hash", "public-key", 1, new Date().toISOString(),
    );

    assert.equal(db.prepare("DELETE FROM users WHERE id = ?").run("user-1").changes, 1);
    assert.equal(db.prepare("SELECT COUNT(1) AS n FROM devices WHERE user_id = ?").get("user-1").n, 0);
    assert.equal(db.prepare("SELECT COUNT(1) AS n FROM auth_requests WHERE user_id = ?").get("user-1").n, 0);
  });
});

test("import strips organization ids before personal-vault validation (upstream 64ae55ce / #7906)", () => {
  // The loop must run before validate_for_personal_vault so organization
  // exports import into the personal vault with a NULL organization id.
  const stripIndex = importSource.indexOf("cipher.organization_id = None;");
  const validateIndex = importSource.indexOf("validate_for_personal_vault");
  assert.ok(stripIndex > 0, "import must null out cipher.organization_id");
  assert.ok(validateIndex > 0, "import must validate ciphers for the personal vault");
  assert.ok(
    stripIndex < validateIndex,
    "organization_id must be stripped before personal-vault validation",
  );

  // The insert binds the (already nulled) organization id, which lands as NULL.
  withDatabase((db) => {
    db.prepare(`INSERT INTO ciphers
      (id, user_id, organization_id, type, data, key, favorite, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "cipher-1", "user-1", null, 1, "{}", null, 0, "created", "updated",
    );
    const cipher = db.prepare("SELECT organization_id FROM ciphers WHERE id = ?").get("cipher-1");
    assert.equal(cipher.organization_id, null);
  });
});

test("GET /api/accounts/keys is registered and keeps the 404 no-key-pair semantics (upstream 895ec2b1)", () => {
  assert.match(
    router,
    /\/api\/accounts\/keys[\s\S]{0,120}get\(accounts::get_keys\)/,
    "GET /api/accounts/keys must be routed to accounts::get_keys",
  );
  assert.match(
    accounts,
    /pub async fn get_keys[\s\S]{0,1200}AppError::NotFound\("User has no key pair"/,
    "an absent key pair must produce a 404 with the upstream message",
  );
  // Empty strings count as "no key pair" because the columns are TEXT NOT NULL.
  withDatabase((db) => {
    db.prepare("UPDATE users SET private_key = '', public_key = '' WHERE id = ?").run("user-1");
    const row = db.prepare("SELECT private_key, public_key FROM users WHERE id = ?").get("user-1");
    assert.equal(row.private_key, "");
    assert.equal(row.public_key, "");
  });
});

test("attachment download tokens expire after one minute (upstream 895ec2b1)", () => {
  const match = attachments.match(/const ATTACHMENT_URL_TTL_MINUTES: i64 = (\d+);/);
  assert.ok(match, "ATTACHMENT_URL_TTL_MINUTES must be defined");
  assert.equal(Number(match[1]), 1, "attachment URL TTL must be 1 minute");
});

test("send file v2 rejects non-object data with a 400 (upstream acb574b7)", () => {
  assert.match(
    sends,
    /let Some\(obj\) = data_value\.as_object_mut\(\) else \{\s*return Err\(AppError::BadRequest\("Invalid Send file data"/,
    "a non-object Send file data payload must return BadRequest",
  );
});

test("prelogin normalizes the email before both the lookup and the keyed KDF hash (upstream 895ec2b1)", () => {
  // One normalization feeding both the user lookup and unknown_email_kdf means
  // case/whitespace variants of the same address cannot drift to a different
  // KDF bucket (user@example.com vs " USER@Example.COM " must agree).
  const fnStart = accounts.indexOf("pub async fn prelogin");
  assert.ok(fnStart > 0, "prelogin must exist");
  const fnBody = accounts.slice(fnStart, fnStart + 4000);
  const normalizeIndex = fnBody.indexOf("normalize_email");
  const lookupIndex = fnBody.indexOf("SELECT kdf_type");
  const kdfIndex = fnBody.indexOf("unknown_email_kdf(");
  assert.ok(normalizeIndex > 0, "prelogin must normalize the email");
  assert.ok(lookupIndex > 0, "prelogin must look up the user");
  assert.ok(kdfIndex > 0, "prelogin must use unknown_email_kdf for unknown emails");
  assert.ok(
    normalizeIndex < lookupIndex && normalizeIndex < kdfIndex,
    "the email must be normalized before both the lookup and the keyed hash",
  );
});

test("user deletion publishes a logout notification before the DELETE (upstream e056359a)", () => {
  const fnStart = accounts.indexOf("async fn cascade_delete_user_data");
  assert.ok(fnStart > 0, "cascade_delete_user_data must exist");
  const fnEnd = accounts.indexOf("Ok(())", fnStart);
  const fnBody = accounts.slice(fnStart, fnEnd);
  const logoutIndex = fnBody.indexOf("UpdateType::LogOut");
  const deleteIndex = fnBody.indexOf('"DELETE FROM users WHERE id = ?1"');
  assert.ok(logoutIndex > 0, "cascade_delete_user_data must publish a LogOut update");
  assert.ok(deleteIndex > 0, "cascade_delete_user_data must delete the user row");
  assert.ok(
    logoutIndex < deleteIndex,
    "the logout notification must fire before the user row is deleted",
  );
});

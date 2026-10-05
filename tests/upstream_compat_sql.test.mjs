import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

const baseline = readFileSync(new URL("../sql/schema.sql", import.meta.url), "utf8");
const sends = readFileSync(new URL("../src/handlers/sends.rs", import.meta.url), "utf8");
const accounts = readFileSync(new URL("../src/handlers/accounts.rs", import.meta.url), "utf8");

function sqlConstant(source, name) {
  const match = source.match(new RegExp(`const ${name}: &str =\\s*"([^"]+)";`));
  assert.ok(match, `${name} must be defined by the handler`);
  return match[1];
}

function withDatabase(run) {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(baseline);
    db.prepare(`INSERT INTO users
      (id, email, master_password_hash, key, private_key, public_key, security_stamp, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "user-1", "user@example.com", "password-verifier", "user-key", "", "", "stamp", "created", "updated",
    );
    db.prepare(`INSERT INTO sends
      (id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iter,
       max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "send-1", "user-1", 1, "encrypted-name", "encrypted-notes", '{"id":"file-1","fileName":"encrypted-file","size":"123"}',
      "old-wrapped-key", "password-hash", "salt", 100000, 2, 0, "created", "updated", "expiration", "deletion", 0, 1,
    );
    run(db);
  } finally {
    db.close();
  }
}

test("Send key rotation preserves encrypted content, password and access restrictions", () => {
  withDatabase((db) => {
    const before = db.prepare("SELECT * FROM sends WHERE id = ?").get("send-1");
    const rotate = db.prepare(sqlConstant(sends, "ROTATE_SEND_KEY_SQL"));
    assert.equal(rotate.run("foreign-key", "wrong-revision", "send-1", "another-user").changes, 0);
    assert.equal(rotate.run("new-wrapped-key", "rotation-revision", "send-1", "user-1").changes, 1);
    const after = db.prepare("SELECT * FROM sends WHERE id = ?").get("send-1");
    assert.deepEqual({ ...after, key: before.key, updated_at: before.updated_at }, { ...before });
    assert.equal(after.key, "new-wrapped-key");
    assert.equal(after.updated_at, "rotation-revision");
  });
});

test("atomic Send access accounting stops at the limit and leaves denied requests unchanged", () => {
  withDatabase((db) => {
    const count = db.prepare(sqlConstant(sends, "REGISTER_SEND_ACCESS_SQL"));
    assert.equal(count.run("first", "send-1").changes, 1);
    assert.equal(count.run("second", "send-1").changes, 1);
    assert.equal(count.run("denied", "send-1").changes, 0);
    const send = db.prepare("SELECT access_count, updated_at FROM sends WHERE id = ?").get("send-1");
    assert.equal(send.access_count, 2);
    assert.equal(send.updated_at, "second");
    db.prepare("UPDATE sends SET max_access_count = NULL WHERE id = ?").run("send-1");
    assert.equal(count.run("unlimited", "send-1").changes, 1);
  });
});

test("account keypair initialization never overwrites either existing key", () => {
  withDatabase((db) => {
    const initialize = db.prepare(sqlConstant(accounts, "SET_INITIAL_KEYPAIR_SQL"));
    assert.equal(initialize.run("private", "public", "first", "another-user").changes, 0);
    for (const [privateKey, publicKey] of [["existing-private", ""], ["", "existing-public"]]) {
      db.prepare("UPDATE users SET private_key = ?, public_key = ? WHERE id = ?").run(privateKey, publicKey, "user-1");
      assert.equal(initialize.run("replacement", "replacement", "denied", "user-1").changes, 0);
    }
    db.prepare("UPDATE users SET private_key = '', public_key = '' WHERE id = ?").run("user-1");
    assert.equal(initialize.run("private", "public", "first", "user-1").changes, 1);
    assert.equal(initialize.run("replacement", "replacement", "denied", "user-1").changes, 0);
    assert.equal(db.prepare("SELECT private_key FROM users WHERE id = ?").get("user-1").private_key, "private");
  });
});

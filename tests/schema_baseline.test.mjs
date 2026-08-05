import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const schema = readFileSync(join(repositoryRoot, "sql", "schema.sql"), "utf8");

function rustFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return rustFiles(path);
    return extname(path) === ".rs" ? [path] : [];
  });
}

test("schema is the only database upgrade source", () => {
  assert.equal(existsSync(join(repositoryRoot, "sql", "migrations")), false);
  assert.doesNotMatch(schema, /users_single_user_before_insert/);

  for (const table of [
    "organizations",
    "users_organizations",
    "collections",
    "groups",
    "org_policies",
    "organization_api_key",
    "events",
    "emergency_access",
    "two_factor_external",
    "two_factor_incomplete",
    "twofactor_duo_ctx",
    "registration_tokens",
    "notification_outbox",
  ]) {
    assert.match(schema, new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(`));
  }

  assert.match(schema, /organization_api_key[\s\S]*?api_key TEXT NOT NULL/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS devices[\s\S]*?push_token TEXT[\s\S]*?push_uuid TEXT/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS cipher_attachments[\s\S]*?user_id TEXT,/);
});

test("runtime Rust code does not mutate the database schema", () => {
  for (const path of rustFiles(join(repositoryRoot, "src"))) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, /\b(?:CREATE|ALTER|DROP)\s+(?:TABLE|INDEX|TRIGGER)\b/i, path);
  }
});

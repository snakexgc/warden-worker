import assert from "node:assert/strict";
import test from "node:test";

import {
  getHeavyDoName,
  normalizePathname,
  shouldOffloadToHeavyDo,
} from "../src/heavy_do_routing.mjs";

const PASSWORD_ENDPOINTS = [
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
  "/api/two-factor/authenticator/disable",
  "/api/webauthn/credential-id/delete",
];

test("all server-password endpoints are routed to HeavyDo", () => {
  for (const path of PASSWORD_ENDPOINTS) {
    assert.equal(shouldOffloadToHeavyDo(path), true, path);
    assert.equal(shouldOffloadToHeavyDo(normalizePathname(path + "/")), true, path + "/");
  }
});

test("unrelated account reads remain on the entry Worker", () => {
  assert.equal(shouldOffloadToHeavyDo("/api/accounts/profile"), false);
  assert.equal(shouldOffloadToHeavyDo("/api/accounts/revision-date"), false);
});

test("heavy routes are deterministically sharded without exposing identity", async () => {
  const first = new Request("https://vault.test/identity/accounts/prelogin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "User@Example.com" }),
  });
  const second = new Request("https://vault.test/identity/accounts/prelogin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "user@example.com" }),
  });
  const other = new Request("https://vault.test/identity/accounts/prelogin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "other@example.com" }),
  });

  const firstName = await getHeavyDoName(first);
  assert.equal(firstName, await getHeavyDoName(second));
  assert.notEqual(firstName, await getHeavyDoName(other));
  assert.match(firstName, /^vault-[0-9a-f]{24}$/);
  assert.doesNotMatch(firstName, /example/);
});

test("organization routes are offloaded to HeavyDo", () => {
  assert.equal(shouldOffloadToHeavyDo("/api/organizations"), true);
  assert.equal(shouldOffloadToHeavyDo("/api/organizations/org-id/users"), true);
  assert.equal(shouldOffloadToHeavyDo("/api/collections"), true);
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  getHeavyDoName,
  normalizePathname,
  shouldOffloadToHeavyDo,
} from "../src/heavy_do_routing.mjs";

const PASSWORD_ENDPOINTS = [
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
  "/api/accounts/key-management/rotate-user-account-keys",
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

test("all heavy routes share one personal-vault Durable Object", () => {
  assert.equal(getHeavyDoName(), "personal-vault");
});

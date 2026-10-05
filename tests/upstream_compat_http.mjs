// Run against a fresh, isolated Wrangler instance with ALLOWED_EMAILS set to
// upstream-sync@example.invalid: node tests/upstream_compat_http.mjs <local-url>
import assert from "node:assert/strict";

const base = new URL(process.argv[2] ?? "http://127.0.0.1:8795");
assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(base.hostname), "use an isolated local Worker");
let assertions = 0;

async function request(path, { method = "GET", body, token, form, expected = 200 } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";
  if (form instanceof URLSearchParams) headers["Content-Type"] = "application/x-www-form-urlencoded";
  const response = await fetch(new URL(path, base), {
    method, headers, body: body ? JSON.stringify(body) : form,
  });
  const raw = await response.text();
  assert.ok([expected].flat().includes(response.status), `${method} ${path}: ${response.status}, expected ${expected}`);
  assertions++;
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return raw; }
}

const config = await request("/api/config");
assert.equal(config.settings.disableUserRegistration, false, "the test requires a fresh database");
assert.equal(config.featureStates["undetermined-cipher-scenario-logic"], true);
assert.equal(config.featureStates["windows-native-credential-sync"], true);
for (const path of [
  "/identity/accounts/register", "/api/accounts/prelogin", "/api/sends/file",
  "/api/sends/access/AAAAAAAAAAAAAAAAAAAAAQ",
  "/api/sends/00000000-0000-0000-0000-000000000001/access/file/file-1",
]) {
  await request(path, { method: "POST", expected: [404, 405] });
}
await request("/api/two-factor/disable", { method: "POST", expected: 405 });
await request("/api/two-factor/disable", { method: "PUT", expected: 401 });
await request("/identity/accounts/prelogin/password", { method: "POST", body: { email: "upstream-sync@example.invalid" } });

const email = "upstream-sync@example.invalid";
const kdf = { kdfType: 0, iterations: 600000 };
const registration = {
  email: `  ${email.toUpperCase()}  `,
  name: "Ignored request name",
  userAsymmetricKeys: { publicKey: "public-key", encryptedPrivateKey: "private-key" },
  MasterPasswordAuthentication: { Kdf: kdf, Salt: email, MasterPasswordAuthenticationHash: "password-hash" },
  MasterPasswordUnlock: { kdf, salt: email, masterKeyWrappedUserKey: "wrapped-user-key" },
};
await request("/identity/accounts/register/finish", { method: "POST", body: registration, expected: 400 });
await request("/identity/accounts/register/finish", {
  method: "POST", body: { ...registration, emailVerificationToken: "invalid-token" }, expected: 400,
});
const verificationToken = await request("/identity/accounts/register/send-verification-email", {
  method: "POST", body: { email: registration.email, name: "Token name", receiveMarketingEmails: false },
});
assert.equal(typeof verificationToken, "string");
const registered = await request("/identity/accounts/register/finish", {
  method: "POST", body: { ...registration, emailVerificationToken: verificationToken },
});
assert.deepEqual(registered, { object: "registerFinish" });

async function login(password) {
  return request("/identity/connect/token", {
    method: "POST", form: new URLSearchParams({
      grant_type: "password", client_id: "web", scope: "api offline_access", username: email, password,
      deviceIdentifier: "sync-test-device", deviceName: "Sync test", deviceType: "14",
    }),
  });
}
let tokens = await login("password-hash");
assert.ok(!Object.hasOwn(tokens, "ResetMasterPassword"));
const profile = await request("/api/accounts/profile", { token: tokens.access_token });
assert.equal(profile.name, "Token name");
const claims = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url"));
assert.equal(claims.email_verified, profile.emailVerified);
await request("/api/accounts/keys", {
  method: "POST", token: tokens.access_token,
  body: { publicKey: "replacement-public", encryptedPrivateKey: "replacement-private" }, expected: 400,
});

const deletionDate = new Date(Date.now() + 86400000).toISOString();
function sendBody(type, extra = {}) {
  return {
    type, key: "wrapped-send-key", name: "encrypted-name", notes: "encrypted-notes",
    deletionDate, disabled: false, hideEmail: true,
    ...(type === 0 ? { text: { text: "encrypted-text", hidden: false } } : { file: { fileName: "encrypted-file-name" } }),
    ...extra,
  };
}
const ownedSend = (send) => request(`/api/sends/${send.id}`, { token: tokens.access_token });
async function sendToken(send) {
  const result = await request("/identity/connect/token", {
    method: "POST", form: new URLSearchParams({
      grant_type: "send_access", client_id: "web", send_id: send.accessId,
    }),
  });
  return result.access_token;
}

const textSend = await request("/api/sends", {
  method: "POST", token: tokens.access_token, body: sendBody(0, { maxAccessCount: 2 }),
});
const textToken = await sendToken(textSend);
assert.equal((await ownedSend(textSend)).accessCount, 0, "issuing a token must not consume an access");
const accesses = await Promise.all(Array.from({ length: 5 }, () => fetch(new URL("/api/sends/access", base), {
  method: "POST", headers: { Authorization: `Bearer ${textToken}` },
})));
assert.equal(accesses.filter((response) => response.status === 200).length, 2);
assert.equal(accesses.filter((response) => response.status === 404).length, 3);
for (const response of accesses) {
  const value = await response.json();
  if (response.status === 200) assert.equal(value.id, textSend.accessId);
}
assert.equal((await ownedSend(textSend)).accessCount, 2);
await request("/api/sends/access", { method: "POST", token: textToken, expected: 404 });

const fileBytes = new Uint8Array([1, 2, 3]);
const fileResult = await request("/api/sends/file/v2", {
  method: "POST", token: tokens.access_token, body: sendBody(1, { fileLength: fileBytes.length, maxAccessCount: 1 }),
});
const fileSend = fileResult.sendResponse;
assert.ok(fileSend?.file?.id);
const upload = new FormData();
upload.set("data", new Blob([fileBytes]), fileSend.file.fileName);
await request(`/api/sends/${fileSend.id}/file/${fileSend.file.id}`, {
  method: "POST", token: tokens.access_token, form: upload,
});
const fileToken = await sendToken(fileSend);
await request("/api/sends/access", { method: "POST", token: fileToken });
assert.equal((await ownedSend(fileSend)).accessCount, 0, "viewing file metadata must not consume an access");
await request("/api/sends/access/file/wrong-file", { method: "POST", token: fileToken, expected: 404 });
assert.equal((await ownedSend(fileSend)).accessCount, 0, "invalid files must not consume an access");
const download = await request(`/api/sends/access/file/${fileSend.file.id}`, { method: "POST", token: fileToken });
const downloaded = await fetch(new URL(download.url, base));
assert.equal(downloaded.status, 200);
assert.deepEqual(new Uint8Array(await downloaded.arrayBuffer()), fileBytes);
assert.equal((await ownedSend(fileSend)).accessCount, 1);
await request(`/api/sends/access/file/${fileSend.file.id}`, { method: "POST", token: fileToken, expected: 404 });

const unlimited = await request("/api/sends", { method: "POST", token: tokens.access_token, body: sendBody(0) });
const wrongTypeToken = await sendToken(unlimited);
await request(`/api/sends/access/file/${fileSend.file.id}`, { method: "POST", token: wrongTypeToken, expected: 400 });
assert.equal((await ownedSend(unlimited)).accessCount, 0);
const beforeRotation = await ownedSend(fileSend);
const cipher = await request("/api/ciphers", {
  method: "POST", token: tokens.access_token, body: { type: 1, name: "encrypted-cipher", login: {} },
});
await request("/api/ciphers/delete", {
  method: "POST", token: tokens.access_token, body: { ids: [cipher.id, cipher.id] },
});
await request(`/api/ciphers/${cipher.id}`, { token: tokens.access_token, expected: 404 });
const rotationSend = { ...sendBody(1), id: fileSend.id, key: "rotated-send-key", name: "must-be-ignored", deletionDate: "invalid-date" };
const rotate = {
  accountUnlockData: { masterPasswordUnlockData: {
    kdfType: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null, email,
    masterKeyAuthenticationHash: "password-hash", masterKeyEncryptedUserKey: "rotated-user-key",
  } },
  accountKeys: { userKeyEncryptedAccountPrivateKey: "rotated-private", accountPublicKey: "public-key" },
  accountData: { folders: [], ciphers: [], sends: [
    { ...sendBody(0), id: textSend.id, key: "rotated-text-key" }, rotationSend,
    { ...sendBody(0), id: unlimited.id, key: "rotated-unlimited-key" },
  ] },
  oldMasterKeyAuthenticationHash: "password-hash",
};
const missingId = structuredClone(rotate);
missingId.accountData.sends.push(sendBody(0));
await request("/api/accounts/key-management/rotate-user-account-keys", {
  method: "POST", token: tokens.access_token, body: missingId, expected: 400,
});
assert.deepEqual(await ownedSend(fileSend), beforeRotation);
await request("/api/accounts/key-management/rotate-user-account-keys", {
  method: "POST", token: tokens.access_token, body: rotate,
});
tokens = await login("password-hash");
const afterRotation = await ownedSend(fileSend);
assert.equal(afterRotation.key, "rotated-send-key");
for (const field of ["type", "name", "notes", "file", "deletionDate", "expirationDate", "maxAccessCount", "accessCount", "hideEmail", "disabled"]) {
  assert.deepEqual(afterRotation[field], beforeRotation[field], `rotation must preserve ${field}`);
}
await request("/api/accounts/password", {
  method: "POST", token: tokens.access_token, body: {
    masterPasswordHash: "password-hash",
    authenticationData: { Kdf: kdf, Salt: email, MasterPasswordAuthenticationHash: "new-password-hash" },
    unlockData: { kdf, salt: email, masterKeyWrappedUserKey: "new-user-key" },
  },
});
await login("new-password-hash");
console.log(`Upstream HTTP compatibility checks passed (${assertions} requests plus concurrent access and R2 download checks).`);

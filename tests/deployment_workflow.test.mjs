import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/push-cloudflare.yaml", import.meta.url),
  "utf8",
);

test("deployment workflow supports private repositories and serializes deployments", () => {
  assert.match(workflow, /permissions:\s+contents: read/);
  assert.match(workflow, /group: \$\{\{ github\.repository \}\}-cloudflare-deploy/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.doesNotMatch(workflow, /pull_request:/);
});

test("deployment workflow pins the validated Rust toolchain", () => {
  assert.match(workflow, /RUST_TOOLCHAIN: 1\.97\.1/);
  assert.match(
    workflow,
    /rustup toolchain install "\$\{\{ env\.RUST_TOOLCHAIN \}\}" --no-self-update/,
  );
  assert.doesNotMatch(workflow, /rustup toolchain install stable/);
});

test("deployment workflow requires only the API token and can discover account ID", () => {
  assert.match(workflow, /Missing required repository secret CLOUDFLARE_API_TOKEN/);
  assert.match(
    workflow,
    /CLOUDFLARE_ACCOUNT_ID: \$\{\{ secrets\.CLOUDFLARE_ACCOUNT_ID \}\}/,
  );
  assert.match(workflow, /node scripts\/cloudflare-provision\.mjs/);
  assert.doesNotMatch(workflow, /Missing required.*CLOUDFLARE_ACCOUNT_ID/);
});

test("database ID and schema initialization are ordered before the real deploy", () => {
  const provision = workflow.indexOf("node scripts/cloudflare-provision.mjs");
  const databaseIdCheck = workflow.indexOf(
    "Verify database_id was written to Wrangler config",
  );
  const schema = workflow.indexOf("Initialize a newly created D1 database");
  const realDeploy = workflow.indexOf("- name: Deploy Worker");

  assert.ok(provision >= 0);
  assert.ok(databaseIdCheck > provision);
  assert.ok(schema > databaseIdCheck);
  assert.ok(realDeploy > schema);
  assert.match(workflow, /if: steps\.provision\.outputs\.d1_is_new == 'true'/);
  assert.doesNotMatch(workflow, /wrangler d1 migrations apply/);
});

test("workflow delegates Durable Object lifecycle to Wrangler", () => {
  assert.doesNotMatch(workflow, /do_bindings_patch/);
  assert.doesNotMatch(workflow, /workers\/scripts\/.*\/settings/);
  assert.doesNotMatch(workflow, /wrangler-action/);
  assert.doesNotMatch(workflow, /sed -i/);
  assert.doesNotMatch(workflow, /\|\| true/);
});

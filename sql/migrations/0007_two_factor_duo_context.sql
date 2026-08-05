-- Store one-time state for Vaultwarden-compatible Duo Universal Prompt (OIDC).

CREATE TABLE IF NOT EXISTS twofactor_duo_ctx (
    state TEXT PRIMARY KEY NOT NULL,
    user_email TEXT NOT NULL,
    nonce TEXT NOT NULL,
    exp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_twofactor_duo_ctx_exp
    ON twofactor_duo_ctx(exp);

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id       UUID         NOT NULL,
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    user_id         UUID         NOT NULL REFERENCES users(id),
    authorization_id VARCHAR(255) NOT NULL,
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    replaced_by     UUID         REFERENCES refresh_tokens(id),
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_family   ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_hash     ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_tokens_user     ON refresh_tokens (user_id);

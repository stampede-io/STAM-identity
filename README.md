# STAM-identity

[![CI](https://github.com/stampede-io/STAM-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/stampede-io/STAM-identity/actions/workflows/ci.yml)

OAuth2.1 Authorization Server — PKCE, RBAC, rotating refresh tokens with reuse detection, audit events.

## Security

### Refresh Token Rotation

Every time a client exchanges a refresh token for a new access token, the server issues a **new refresh token** and invalidates the old one. This limits the window of exposure if a token is leaked.

Tokens are grouped into **families** — a chain of rotated tokens that all originate from the same login session. The `refresh_tokens` table tracks each token's `family_id`, a SHA-256 hash of its value, and a `replaced_by` pointer to its successor.

### Reuse Detection and Family Revocation

If a previously-used refresh token is replayed (i.e., a token that was already rotated away from), the server treats it as a potential theft and **revokes every token in the family**. This forces all sessions in that rotation chain to re-authenticate.

The server publishes a `RefreshTokenReuseDetectedEvent` (Spring `ApplicationEvent`) when reuse is detected, carrying the `principalName` and `familyId`. Downstream listeners can use this for audit logging or alerting.

### How It Works

1. **Login** — user authenticates via PKCE authorization code flow; the token endpoint returns an access token and refresh token. A row is inserted into `refresh_tokens` with a new `family_id`.
2. **Refresh** — client sends the refresh token to `/oauth2/token`. The server issues a new token pair, inserts a new row with the same `family_id`, and marks the old row as `revoked=true` with `replaced_by` pointing to the new row.
3. **Reuse attempt** — if an already-revoked/replaced token is presented, the server runs `UPDATE refresh_tokens SET revoked = true WHERE family_id = ?`, removes the authorization from the in-memory store, and publishes the audit event. The request returns `400 invalid_grant`.
4. **Expiry** — an expired refresh token simply returns `401` without triggering family revocation; expiry is a normal lifecycle event, not an attack signal.

### Schema

```sql
CREATE TABLE refresh_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id        UUID         NOT NULL,
    token_hash       VARCHAR(255) NOT NULL UNIQUE,
    user_id          UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    authorization_id VARCHAR(255) NOT NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    replaced_by      UUID         REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    expires_at       TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
```

### Key Classes

| Class | Purpose |
|-------|---------|
| `FamilyAwareAuthorizationService` | Wraps the in-memory authorization service; tracks token families in Postgres and detects reuse on `findByToken` |
| `PublicClientRefreshAuthenticationConverter` | Extracts `client_id` from refresh_token grant requests for public (PKCE) clients |
| `PublicClientRefreshAuthenticationProvider` | Authenticates public clients for refresh_token grants (Spring's built-in provider only handles authorization_code) |
| `RefreshTokenReuseDetectedEvent` | Spring ApplicationEvent emitted on reuse detection, carrying `principalName` and `familyId` |

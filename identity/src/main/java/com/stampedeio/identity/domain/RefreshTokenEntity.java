package com.stampedeio.identity.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "authorization_id", nullable = false)
    private String authorizationId;

    @Column(nullable = false)
    private boolean revoked;

    @Column(name = "replaced_by")
    private UUID replacedBy;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected RefreshTokenEntity() {}

    public RefreshTokenEntity(UUID familyId, String tokenHash, UUID userId,
                              String authorizationId, Instant expiresAt) {
        this.familyId = familyId;
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.authorizationId = authorizationId;
        this.revoked = false;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }

    public UUID getFamilyId() { return familyId; }

    public String getTokenHash() { return tokenHash; }

    public UUID getUserId() { return userId; }

    public String getAuthorizationId() { return authorizationId; }

    public boolean isRevoked() { return revoked; }

    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public UUID getReplacedBy() { return replacedBy; }

    public void setReplacedBy(UUID replacedBy) { this.replacedBy = replacedBy; }

    public Instant getExpiresAt() { return expiresAt; }

    public Instant getCreatedAt() { return createdAt; }
}

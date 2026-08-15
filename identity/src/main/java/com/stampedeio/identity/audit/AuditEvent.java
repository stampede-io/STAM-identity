package com.stampedeio.identity.audit;

import java.time.Instant;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AuditEvent.UserLoggedIn.class, name = "UserLoggedIn"),
        @JsonSubTypes.Type(value = AuditEvent.LoginFailed.class, name = "LoginFailed"),
        @JsonSubTypes.Type(value = AuditEvent.TokenRefreshed.class, name = "TokenRefreshed"),
        @JsonSubTypes.Type(value = AuditEvent.RefreshTokenReuseDetected.class, name = "RefreshTokenReuseDetected"),
        @JsonSubTypes.Type(value = AuditEvent.RoleChanged.class, name = "RoleChanged")
})
public sealed interface AuditEvent {

    String type();
    Instant occurredAt();

    record UserLoggedIn(
            UUID userId,
            String email,
            String ip,
            Instant occurredAt,
            String correlationId
    ) implements AuditEvent {
        @Override public String type() { return "UserLoggedIn"; }
    }

    record LoginFailed(
            String email,
            String ip,
            Instant occurredAt,
            String failureReason
    ) implements AuditEvent {
        @Override public String type() { return "LoginFailed"; }
    }

    record TokenRefreshed(
            UUID userId,
            String email,
            Instant occurredAt,
            String correlationId
    ) implements AuditEvent {
        @Override public String type() { return "TokenRefreshed"; }
    }

    record RefreshTokenReuseDetected(
            String email,
            UUID familyId,
            Instant occurredAt
    ) implements AuditEvent {
        @Override public String type() { return "RefreshTokenReuseDetected"; }
    }

    record RoleChanged(
            UUID targetUserId,
            UUID changedBy,
            String oldRole,
            String newRole,
            Instant occurredAt
    ) implements AuditEvent {
        @Override public String type() { return "RoleChanged"; }
    }
}

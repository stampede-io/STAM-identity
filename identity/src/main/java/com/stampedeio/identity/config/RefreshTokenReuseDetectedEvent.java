package com.stampedeio.identity.config;

import java.util.UUID;

import org.springframework.context.ApplicationEvent;

public class RefreshTokenReuseDetectedEvent extends ApplicationEvent {

    private final String principalName;
    private final UUID familyId;

    public RefreshTokenReuseDetectedEvent(Object source, String principalName, UUID familyId) {
        super(source);
        this.principalName = principalName;
        this.familyId = familyId;
    }

    public String getPrincipalName() { return principalName; }

    public UUID getFamilyId() { return familyId; }
}

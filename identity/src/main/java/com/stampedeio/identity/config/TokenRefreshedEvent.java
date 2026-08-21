package com.stampedeio.identity.config;

import java.util.UUID;

import org.springframework.context.ApplicationEvent;

public class TokenRefreshedEvent extends ApplicationEvent {

    private final String principalName;
    private final UUID userId;

    public TokenRefreshedEvent(Object source, String principalName, UUID userId) {
        super(source);
        this.principalName = principalName;
        this.userId = userId;
    }

    public String getPrincipalName() { return principalName; }

    public UUID getUserId() { return userId; }
}

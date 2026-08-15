package com.stampedeio.identity.audit;

import java.time.Instant;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.stereotype.Component;

import com.stampedeio.identity.config.RefreshTokenReuseDetectedEvent;
import com.stampedeio.identity.config.TokenRefreshedEvent;
import com.stampedeio.identity.domain.UserRepository;

@Component
@ConditionalOnBean(IdentityAuditPublisher.class)
public class AuditEventListener {

    private final IdentityAuditPublisher publisher;
    private final UserRepository userRepository;

    public AuditEventListener(IdentityAuditPublisher publisher, UserRepository userRepository) {
        this.publisher = publisher;
        this.userRepository = userRepository;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication() instanceof OAuth2AuthorizationCodeRequestAuthenticationToken) {
            return;
        }

        String email = event.getAuthentication().getName();
        userRepository.findByEmail(email).ifPresent(user ->
                publisher.publish(new AuditEvent.UserLoggedIn(
                        user.getId(),
                        email,
                        null,
                        Instant.now(),
                        UUID.randomUUID().toString()
                ))
        );
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String email = event.getAuthentication().getName();
        String reason = event.getException().getMessage();

        publisher.publish(new AuditEvent.LoginFailed(
                email,
                null,
                Instant.now(),
                reason
        ));
    }

    @EventListener
    public void onTokenRefreshed(TokenRefreshedEvent event) {
        publisher.publish(new AuditEvent.TokenRefreshed(
                event.getUserId(),
                event.getPrincipalName(),
                Instant.now(),
                UUID.randomUUID().toString()
        ));
    }

    @EventListener
    public void onRefreshTokenReuse(RefreshTokenReuseDetectedEvent event) {
        publisher.publish(new AuditEvent.RefreshTokenReuseDetected(
                event.getPrincipalName(),
                event.getFamilyId(),
                Instant.now()
        ));
    }
}

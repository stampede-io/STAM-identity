package com.stampedeio.identity.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.transaction.annotation.Transactional;

import com.stampedeio.identity.domain.RefreshTokenEntity;
import com.stampedeio.identity.domain.RefreshTokenRepository;

public class FamilyAwareAuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(FamilyAwareAuthorizationService.class);

    private final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;

    public FamilyAwareAuthorizationService(RefreshTokenRepository refreshTokenRepository,
                                           ApplicationEventPublisher eventPublisher) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.eventPublisher = eventPublisher;
    }

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization existing = delegate.findById(authorization.getId());
        delegate.save(authorization);
        trackRefreshToken(authorization, existing);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    @Transactional
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2Authorization authorization = delegate.findByToken(token, tokenType);

        if (authorization == null || !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return authorization;
        }

        String hash = hashToken(token);
        Optional<RefreshTokenEntity> entry = refreshTokenRepository.findByTokenHash(hash);

        if (entry.isEmpty()) {
            return authorization;
        }

        RefreshTokenEntity tokenEntity = entry.get();

        if (tokenEntity.isRevoked() || tokenEntity.getReplacedBy() != null) {
            UUID familyId = tokenEntity.getFamilyId();
            log.warn("Refresh token reuse detected for family {}; revoking entire family", familyId);

            refreshTokenRepository.revokeByFamilyId(familyId);
            delegate.remove(authorization);

            eventPublisher.publishEvent(new RefreshTokenReuseDetectedEvent(
                    this, authorization.getPrincipalName(), familyId));

            return null;
        }

        return authorization;
    }

    private void trackRefreshToken(OAuth2Authorization authorization, OAuth2Authorization existing) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenEntry = authorization.getRefreshToken();
        if (refreshTokenEntry == null || refreshTokenEntry.getToken() == null) {
            return;
        }

        String newTokenValue = refreshTokenEntry.getToken().getTokenValue();
        String newHash = hashToken(newTokenValue);

        if (refreshTokenRepository.findByTokenHash(newHash).isPresent()) {
            return;
        }

        UUID familyId;
        UUID userId = extractUserId(authorization);

        if (existing != null && existing.getRefreshToken() != null) {
            String oldTokenValue = existing.getRefreshToken().getToken().getTokenValue();
            String oldHash = hashToken(oldTokenValue);
            Optional<RefreshTokenEntity> oldEntry = refreshTokenRepository.findByTokenHash(oldHash);

            if (oldEntry.isPresent()) {
                RefreshTokenEntity old = oldEntry.get();
                familyId = old.getFamilyId();

                RefreshTokenEntity newEntity = new RefreshTokenEntity(
                        familyId, newHash, userId, authorization.getId(),
                        refreshTokenEntry.getToken().getExpiresAt());
                refreshTokenRepository.save(newEntity);

                old.setReplacedBy(newEntity.getId());
                old.setRevoked(true);
                refreshTokenRepository.save(old);
                return;
            }
        }

        familyId = UUID.randomUUID();
        RefreshTokenEntity newEntity = new RefreshTokenEntity(
                familyId, newHash, userId, authorization.getId(),
                refreshTokenEntry.getToken().getExpiresAt());
        refreshTokenRepository.save(newEntity);
    }

    private UUID extractUserId(OAuth2Authorization authorization) {
        try {
            return UUID.fromString(authorization.getPrincipalName());
        } catch (IllegalArgumentException e) {
            return UUID.nameUUIDFromBytes(
                    authorization.getPrincipalName().getBytes(StandardCharsets.UTF_8));
        }
    }

    static String hashToken(String tokenValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tokenValue.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}

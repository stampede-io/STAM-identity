package com.stampedeio.identity.config;

import java.time.Instant;
import java.util.Base64;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator tokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        if (isPublicClientWithoutOfflineAccess(context)) {
            return null;
        }
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient()
                .getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(tokenGenerator.generateKey(), issuedAt, expiresAt);
    }

    private static boolean isPublicClientWithoutOfflineAccess(OAuth2TokenContext context) {
        if (!context.getRegisteredClient().getClientAuthenticationMethods()
                .contains(ClientAuthenticationMethod.NONE)) {
            return false;
        }
        return !context.getAuthorizedScopes().contains("offline_access");
    }
}

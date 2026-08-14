package com.stampedeio.identity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

final class PublicClientRefreshAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(PublicClientRefreshAuthenticationProvider.class);

    private final RegisteredClientRepository registeredClientRepository;

    PublicClientRefreshAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuth = (OAuth2ClientAuthenticationToken) authentication;

        if (!ClientAuthenticationMethod.NONE.equals(clientAuth.getClientAuthenticationMethod())) {
            return null;
        }

        // Only handle when credentials are null (refresh_token grant, no code_verifier)
        if (clientAuth.getCredentials() != null) {
            return null;
        }

        String clientId = clientAuth.getPrincipal().toString();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client not found", null));
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                            "Client does not support NONE authentication", null));
        }

        log.debug("Authenticated public client '{}' for refresh_token grant", clientId);

        return new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

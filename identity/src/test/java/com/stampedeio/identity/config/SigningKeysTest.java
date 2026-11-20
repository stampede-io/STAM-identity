package com.stampedeio.identity.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.RSAKey;

/**
 * STAM-454: identity used to generate a fresh key on every start under a
 * fixed kid, so validators kept the old key for that kid and 401'd every
 * new token until they restarted.
 */
class SigningKeysTest {

    private static String pkcs8Base64;

    @BeforeAll
    static void makeKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        pkcs8Base64 = Base64.getEncoder().encodeToString(gen.generateKeyPair().getPrivate().getEncoded());
    }

    @Test
    void configuredKey_isTheSameKeyAndKidOnEveryStart() throws Exception {
        // Two restarts, or two replicas, given the same secret.
        RSAKey first = SigningKeys.load(pkcs8Base64);
        RSAKey second = SigningKeys.load(pkcs8Base64);

        assertThat(second.getKeyID()).isEqualTo(first.getKeyID());
        assertThat(second.toPublicJWK()).isEqualTo(first.toPublicJWK());
        assertThat(first.isPrivate()).isTrue();
    }

    @Test
    void kidIsTheKeysThumbprint() throws Exception {
        RSAKey key = SigningKeys.load(pkcs8Base64);
        assertThat(key.getKeyID()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    void generatedKeys_getDifferentKids_soValidatorsRefetchInsteadOfMismatching() throws Exception {
        // No secret configured (local dev): each start still makes a new key,
        // but under a new kid, which validators treat as unknown and refetch.
        RSAKey first = SigningKeys.load("");
        RSAKey second = SigningKeys.load(null);

        assertThat(second.getKeyID()).isNotEqualTo(first.getKeyID());
    }

    @Test
    void acceptsPemAsWellAsBareBase64() throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + pkcs8Base64.replaceAll("(.{64})", "$1\n")
                + "\n-----END PRIVATE KEY-----\n";

        assertThat(SigningKeys.load(pem).getKeyID()).isEqualTo(SigningKeys.load(pkcs8Base64).getKeyID());
    }

    @Test
    void rejectsGarbageInsteadOfSilentlyGeneratingAKey() {
        // A typo in the secret must fail startup, not quietly fall back to a
        // per-start key and bring STAM-454 back.
        assertThatThrownBy(() -> SigningKeys.load("not-a-key")).isInstanceOf(IllegalStateException.class);
    }
}

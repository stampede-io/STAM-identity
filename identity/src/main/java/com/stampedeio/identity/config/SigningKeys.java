package com.stampedeio.identity.config;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import com.nimbusds.jose.jwk.RSAKey;

/**
 * The JWT signing key (STAM-454).
 *
 * <p>With {@code IDENTITY_RSA_PRIVATE_KEY} set (an RSA PKCS#8 key, PEM or bare
 * base64), every restart and every replica signs with the same key, so tokens
 * stay valid across deploys. Without it, a key is generated per start, which
 * is fine for local dev only.
 *
 * <p>Either way the {@code kid} is the key's RFC 7638 thumbprint. A new key
 * therefore gets a new {@code kid}, and the gateway, catalog and booking
 * refetch the JWKS for an unknown {@code kid} instead of checking the
 * signature against the old key they cached under a reused one.
 */
final class SigningKeys {

    private SigningKeys() {
    }

    static RSAKey load(String pkcs8) {
        try {
            RSAPrivateCrtKey privateKey;
            if (pkcs8 == null || pkcs8.isBlank()) {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                privateKey = (RSAPrivateCrtKey) gen.generateKeyPair().getPrivate();
            } else {
                String body = pkcs8.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
                privateKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            }
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return new RSAKey.Builder(publicKey).privateKey(privateKey).keyIDFromThumbprint().build();
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "IDENTITY_RSA_PRIVATE_KEY is not a valid RSA PKCS#8 private key (PEM or base64). "
                            + "A PKCS#1 key (base64 starting 'MIIEow', or 'BEGIN RSA PRIVATE KEY') must be converted: "
                            + "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
                            + "| openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0", ex);
        }
    }
}

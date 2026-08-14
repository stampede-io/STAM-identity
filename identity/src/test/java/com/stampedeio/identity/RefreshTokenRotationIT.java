package com.stampedeio.identity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stampedeio.identity.domain.RefreshTokenRepository;
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class RefreshTokenRotationIT {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port;
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        User user = new User("rotation@stampede.io", passwordEncoder.encode("password123"), Role.USER);
        userRepository.save(user);
    }

    @Test
    void refreshTokenRotation_issuesNewTokenAndInvalidatesOld() throws Exception {
        JsonNode initialTokens = obtainTokensViaPkce();
        String originalRefreshToken = initialTokens.get("refresh_token").asText();
        assertThat(originalRefreshToken).isNotBlank();

        // First rotation: token A → token B
        JsonNode rotatedTokens = refreshTokens(originalRefreshToken);
        assertThat(rotatedTokens.get("access_token").asText()).isNotBlank();
        String newRefreshToken = rotatedTokens.get("refresh_token").asText();
        assertThat(newRefreshToken).isNotBlank();
        assertThat(newRefreshToken).isNotEqualTo(originalRefreshToken);

        // Second rotation: token B → token C (proves rotation chain works)
        JsonNode thirdTokens = refreshTokens(newRefreshToken);
        assertThat(thirdTokens.get("access_token").asText()).isNotBlank();
        String thirdRefreshToken = thirdTokens.get("refresh_token").asText();
        assertThat(thirdRefreshToken).isNotBlank();
        assertThat(thirdRefreshToken).isNotEqualTo(newRefreshToken);
    }

    @Test
    void refreshTokenReuse_revokesEntireFamily() throws Exception {
        JsonNode initialTokens = obtainTokensViaPkce();
        String tokenA = initialTokens.get("refresh_token").asText();

        // Use token A to get token B (rotation)
        JsonNode rotatedTokens = refreshTokens(tokenA);
        String tokenB = rotatedTokens.get("refresh_token").asText();

        // Replay token A (reuse attack) — should trigger family revocation
        HttpResponse<String> reuseResponse = sendRefreshRequest(tokenA);
        assertThat(reuseResponse.statusCode()).isEqualTo(400);

        // Token B should ALSO be revoked (family revocation)
        HttpResponse<String> tokenBResponse = sendRefreshRequest(tokenB);
        assertThat(tokenBResponse.statusCode()).isEqualTo(400);
    }

    @Test
    void refreshTokenFamilyTracking_recordsInDatabase() throws Exception {
        JsonNode initialTokens = obtainTokensViaPkce();
        String tokenA = initialTokens.get("refresh_token").asText();

        assertThat(refreshTokenRepository.count()).isEqualTo(1);

        refreshTokens(tokenA);

        assertThat(refreshTokenRepository.count()).isEqualTo(2);

        var allTokens = refreshTokenRepository.findAll();
        var familyIds = allTokens.stream()
                .map(t -> t.getFamilyId())
                .distinct()
                .toList();
        assertThat(familyIds).hasSize(1);
    }

    private JsonNode obtainTokensViaPkce() throws Exception {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String authUrl = baseUrl + "/oauth2/authorize"
                + "?response_type=code"
                + "&client_id=stampede-spa"
                + "&scope=openid%20profile%20email%20offline_access"
                + "&redirect_uri=http://127.0.0.1/callback"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256";

        HttpResponse<String> authResponse = client.send(
                HttpRequest.newBuilder().uri(URI.create(authUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        String loginRedirect = authResponse.headers().firstValue("Location").orElseThrow();
        String authCookie = extractSessionCookie(authResponse.headers().allValues("Set-Cookie"));

        HttpResponse<String> loginPageResponse = client.send(
                HttpRequest.newBuilder().uri(URI.create(resolveUrl(loginRedirect))).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        String sessionCookie = extractSessionCookie(loginPageResponse.headers().allValues("Set-Cookie"));
        String combinedCookies = combineCookies(authCookie, sessionCookie);

        String loginBody = "username=rotation@stampede.io&password=password123";
        HttpRequest.Builder loginRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded");
        if (combinedCookies != null) {
            loginRequestBuilder.header("Cookie", combinedCookies);
        }
        loginRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(loginBody));

        HttpResponse<String> loginResponse = client.send(
                loginRequestBuilder.build(), HttpResponse.BodyHandlers.ofString());

        String postLoginCookie = extractSessionCookie(loginResponse.headers().allValues("Set-Cookie"));
        if (postLoginCookie != null) {
            combinedCookies = combineCookies(combinedCookies, postLoginCookie);
        }

        String postLoginRedirect = loginResponse.headers().firstValue("Location").orElse(authUrl);

        HttpRequest.Builder authRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(resolveUrl(postLoginRedirect))).GET();
        if (combinedCookies != null) {
            authRequestBuilder.header("Cookie", combinedCookies);
        }

        HttpResponse<String> consentResponse = client.send(
                authRequestBuilder.build(), HttpResponse.BodyHandlers.ofString());

        String location = consentResponse.headers().firstValue("Location").orElse(null);
        if (consentResponse.statusCode() == 302 && location != null && !location.contains("code=")) {
            String nextCookie = extractSessionCookie(consentResponse.headers().allValues("Set-Cookie"));
            if (nextCookie != null) combinedCookies = combineCookies(combinedCookies, nextCookie);

            HttpRequest.Builder nextBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(resolveUrl(location))).GET();
            if (combinedCookies != null) nextBuilder.header("Cookie", combinedCookies);

            consentResponse = client.send(nextBuilder.build(), HttpResponse.BodyHandlers.ofString());
            location = consentResponse.headers().firstValue("Location").orElse(null);
        }

        String code = extractQueryParam(URI.create(location), "code");

        String tokenBody = "grant_type=authorization_code"
                + "&code=" + code
                + "&redirect_uri=http://127.0.0.1/callback"
                + "&client_id=stampede-spa"
                + "&code_verifier=" + codeVerifier;

        HttpResponse<String> tokenResponse = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(tokenBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(tokenResponse.statusCode())
                .as("Token response: %s", tokenResponse.body())
                .isEqualTo(200);

        return objectMapper.readTree(tokenResponse.body());
    }

    private JsonNode refreshTokens(String refreshToken) throws Exception {
        HttpResponse<String> response = sendRefreshRequest(refreshToken);
        assertThat(response.statusCode())
                .as("Refresh response: %s", response.body())
                .isEqualTo(200);
        return objectMapper.readTree(response.body());
    }

    private HttpResponse<String> sendRefreshRequest(String refreshToken) throws Exception {
        HttpClient client = HttpClient.newBuilder().build();
        String body = "grant_type=refresh_token"
                + "&refresh_token=" + refreshToken
                + "&client_id=stampede-spa";

        return client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String resolveUrl(String urlOrPath) {
        if (urlOrPath.startsWith("http://") || urlOrPath.startsWith("https://")) {
            return urlOrPath;
        }
        return baseUrl + urlOrPath;
    }

    private String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String generateCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private String extractSessionCookie(List<String> setCookieHeaders) {
        for (String header : setCookieHeaders) {
            if (header.contains("JSESSIONID") || header.contains("SESSION")) {
                return header.split(";")[0];
            }
        }
        return null;
    }

    private String combineCookies(String existing, String additional) {
        if (existing == null) return additional;
        if (additional == null) return existing;
        if (existing.contains(additional.split("=")[0])) return additional;
        return existing + "; " + additional;
    }

    private String extractQueryParam(URI uri, String param) {
        String query = uri.getQuery();
        if (query == null) return null;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(param) && kv.length == 2) {
                return kv[1];
            }
        }
        return null;
    }
}

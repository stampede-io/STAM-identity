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
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AuthFlowIT {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port;
        userRepository.deleteAll();
        User user = new User("test@stampede.io", passwordEncoder.encode("password123"), Role.USER);
        userRepository.save(user);
    }

    @Test
    void fullPkceAuthCodeFlow_issuesTokensWithCorrectClaims() throws Exception {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        // Step 1: Initiate authorization request
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

        assertThat(authResponse.statusCode()).isEqualTo(302);
        String loginRedirect = authResponse.headers().firstValue("Location").orElseThrow();
        assertThat(loginRedirect).contains("/login");

        // Step 2: Get the login page to extract session cookie
        HttpResponse<String> loginPageResponse = client.send(
                HttpRequest.newBuilder().uri(URI.create(resolveUrl(loginRedirect))).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        String sessionCookie = extractSessionCookie(loginPageResponse.headers().allValues("Set-Cookie"));
        // Also grab cookie from the initial auth response
        String authCookie = extractSessionCookie(authResponse.headers().allValues("Set-Cookie"));
        String combinedCookies = combineCookies(authCookie, sessionCookie);

        // Step 3: POST login credentials
        String loginBody = "username=test@stampede.io&password=password123";
        HttpRequest.Builder loginRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded");
        if (combinedCookies != null) {
            loginRequestBuilder.header("Cookie", combinedCookies);
        }
        loginRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(loginBody));

        HttpResponse<String> loginResponse = client.send(
                loginRequestBuilder.build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(loginResponse.statusCode()).isIn(302, 200);

        String postLoginCookie = extractSessionCookie(loginResponse.headers().allValues("Set-Cookie"));
        if (postLoginCookie != null) {
            combinedCookies = combineCookies(combinedCookies, postLoginCookie);
        }

        // Step 4: Follow redirect after login (should go back to authorization endpoint)
        String postLoginRedirect = loginResponse.headers().firstValue("Location").orElse(authUrl);
        String resolvedRedirect = resolveUrl(postLoginRedirect);

        HttpRequest.Builder authRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(resolvedRedirect))
                .GET();
        if (combinedCookies != null) {
            authRequestBuilder.header("Cookie", combinedCookies);
        }

        HttpResponse<String> consentResponse = client.send(
                authRequestBuilder.build(),
                HttpResponse.BodyHandlers.ofString());

        // May need to follow one more redirect if login redirected to the saved request
        String location = consentResponse.headers().firstValue("Location").orElse(null);
        if (consentResponse.statusCode() == 302 && location != null && !location.contains("code=")) {
            String nextCookie = extractSessionCookie(consentResponse.headers().allValues("Set-Cookie"));
            if (nextCookie != null) combinedCookies = combineCookies(combinedCookies, nextCookie);

            HttpRequest.Builder nextBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(resolveUrl(location)))
                    .GET();
            if (combinedCookies != null) nextBuilder.header("Cookie", combinedCookies);

            consentResponse = client.send(nextBuilder.build(), HttpResponse.BodyHandlers.ofString());
            location = consentResponse.headers().firstValue("Location").orElse(null);
        }

        assertThat(consentResponse.statusCode()).isEqualTo(302);
        assertThat(location).isNotNull();
        assertThat(location).contains("code=");

        String code = extractQueryParam(URI.create(location), "code");
        assertThat(code).isNotEmpty();

        // Step 5: Exchange authorization code for tokens
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

        JsonNode tokenJson = objectMapper.readTree(tokenResponse.body());
        assertThat(tokenJson.has("access_token"))
                .as("Token response should have access_token: %s", tokenResponse.body())
                .isTrue();
        assertThat(tokenJson.has("refresh_token"))
                .as("Token response should have refresh_token: %s", tokenResponse.body())
                .isTrue();
        assertThat(tokenJson.get("token_type").asText()).isEqualToIgnoringCase("Bearer");

        // Step 6: Decode and verify JWT claims
        String accessToken = tokenJson.get("access_token").asText();
        String[] parts = accessToken.split("\\.");
        assertThat(parts).hasSize(3);

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JsonNode claims = objectMapper.readTree(payload);

        assertThat(claims.has("sub")).isTrue();
        assertThat(claims.has("exp")).isTrue();
        assertThat(claims.has("iat")).isTrue();
        assertThat(claims.has("iss")).isTrue();
        assertThat(claims.get("email").asText()).isEqualTo("test@stampede.io");
        assertThat(claims.get("roles").isArray()).isTrue();
        assertThat(claims.get("roles").get(0).asText()).isEqualTo("USER");

        // Verify access token TTL is <= 10 minutes
        long exp = claims.get("exp").asLong();
        long iat = claims.get("iat").asLong();
        assertThat(exp - iat).isLessThanOrEqualTo(600);
    }

    @Test
    void jwksEndpoint_returnsPublicKey() throws Exception {
        HttpClient client = HttpClient.newBuilder().build();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/oauth2/jwks"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode jwks = objectMapper.readTree(response.body());
        assertThat(jwks.get("keys").size()).isGreaterThan(0);

        JsonNode key = jwks.get("keys").get(0);
        assertThat(key.get("kty").asText()).isEqualTo("RSA");
        assertThat(key.has("n")).isTrue();
        assertThat(key.has("e")).isTrue();
        assertThat(key.get("kid").asText()).isNotEmpty();
    }

    @Test
    void tokenEndpoint_withInvalidCode_failsGracefully() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        String tokenBody = "grant_type=authorization_code"
                + "&code=invalid-code"
                + "&redirect_uri=http://127.0.0.1/callback"
                + "&client_id=stampede-spa"
                + "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(tokenBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isIn(400, 401);
    }

    @Test
    void registerAndLogin_newUser() throws Exception {
        HttpClient client = HttpClient.newBuilder().build();

        String registerBody = """
                {"email":"newuser@stampede.io","password":"securepass123"}
                """;

        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/api/v1/users/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(registerBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(201);
        JsonNode body = objectMapper.readTree(response.body());
        assertThat(body.get("email").asText()).isEqualTo("newuser@stampede.io");
        assertThat(body.get("role").asText()).isEqualTo("USER");
        assertThat(body.has("id")).isTrue();
    }

    @Test
    void register_duplicateEmail_returns409() throws Exception {
        HttpClient client = HttpClient.newBuilder().build();

        String registerBody = """
                {"email":"test@stampede.io","password":"password123"}
                """;

        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + "/api/v1/users/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(registerBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(409);
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

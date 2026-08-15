package com.stampedeio.identity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.stampedeio.identity.audit.AuditEvent;
import com.stampedeio.identity.audit.IdentityAuditPublisher;
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("audit-test")
@Testcontainers
class AuditEventIT {

    @Container
    static KafkaContainer kafka = new KafkaContainer("apache/kafka:3.8.1");

    @DynamicPropertySource
    static void kafkaProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private IdentityAuditPublisher auditPublisher;

    @Autowired
    private KafkaTemplate<String, AuditEvent> kafkaTemplate;

    private String baseUrl;

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port;
        userRepository.deleteAll();
        User user = new User("audit@stampede.io", passwordEncoder.encode("password123"), Role.USER);
        userRepository.save(user);
    }

    @Test
    void publisherSendsEventToKafka() throws Exception {
        AuditEvent.UserLoggedIn event = new AuditEvent.UserLoggedIn(
                UUID.randomUUID(), "direct-test@stampede.io", null, Instant.now(), "test-corr-id");

        kafkaTemplate.send("identity.audit", "test-key", event).get(5, TimeUnit.SECONDS);

        try (KafkaConsumer<String, String> consumer = createStringConsumer()) {
            consumer.subscribe(List.of("identity.audit"));

            String found = null;
            long deadline = System.currentTimeMillis() + 10_000;
            while (System.currentTimeMillis() < deadline) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records) {
                    if (record.value().contains("direct-test@stampede.io")) {
                        found = record.value();
                        break;
                    }
                }
                if (found != null) break;
            }

            assertThat(found).as("Expected event published via KafkaTemplate to appear on identity.audit").isNotNull();
            assertThat(found).contains("UserLoggedIn");
            assertThat(found).contains("direct-test@stampede.io");
        }
    }

    @Test
    void login_emitsUserLoggedInAuditEvent() throws Exception {
        performLogin("audit@stampede.io", "password123");

        Thread.sleep(2000);

        try (KafkaConsumer<String, String> consumer = createStringConsumer()) {
            consumer.subscribe(List.of("identity.audit"));

            String found = null;
            long deadline = System.currentTimeMillis() + 10_000;
            while (System.currentTimeMillis() < deadline) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records) {
                    if (record.value().contains("audit@stampede.io") && record.value().contains("UserLoggedIn")) {
                        found = record.value();
                        break;
                    }
                }
                if (found != null) break;
            }

            assertThat(found).as("Expected UserLoggedIn event on identity.audit topic after login").isNotNull();
        }
    }

    @Test
    void failedLogin_emitsLoginFailedAuditEvent() throws Exception {
        performLogin("audit@stampede.io", "wrong-password");

        Thread.sleep(2000);

        try (KafkaConsumer<String, String> consumer = createStringConsumer()) {
            consumer.subscribe(List.of("identity.audit"));

            String found = null;
            long deadline = System.currentTimeMillis() + 10_000;
            while (System.currentTimeMillis() < deadline) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records) {
                    if (record.value().contains("audit@stampede.io") && record.value().contains("LoginFailed")) {
                        found = record.value();
                        break;
                    }
                }
                if (found != null) break;
            }

            assertThat(found).as("Expected LoginFailed event on identity.audit topic after bad login").isNotNull();
        }
    }

    private void performLogin(String email, String password) throws Exception {
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

        HttpResponse<String> loginPageResponse = client.send(
                HttpRequest.newBuilder().uri(URI.create(resolveUrl(loginRedirect))).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        String sessionCookie = extractSessionCookie(loginPageResponse.headers().allValues("Set-Cookie"));
        String authCookie = extractSessionCookie(authResponse.headers().allValues("Set-Cookie"));
        String combinedCookies = combineCookies(authCookie, sessionCookie);

        String loginBody = "username=" + email + "&password=" + password;
        HttpRequest.Builder loginRequestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded");
        if (combinedCookies != null) {
            loginRequestBuilder.header("Cookie", combinedCookies);
        }
        loginRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(loginBody));

        client.send(loginRequestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private KafkaConsumer<String, String> createStringConsumer() {
        var props = new java.util.Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "audit-it-" + System.currentTimeMillis());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new KafkaConsumer<>(props);
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
}

package com.stampedeio.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.stampedeio.identity.audit.AuditEvent;
import com.stampedeio.identity.audit.IdentityAuditPublisher;
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

/**
 * STAM-456: identity's own API must accept the access tokens identity issues.
 * Before this, /api/** sat on the form-login chain, a bearer token was
 * ignored, and every call was treated as anonymous (302 to /login), so an
 * ADMIN could never change a role with a JWT.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class UserRoleApiIT {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @MockitoBean
    private IdentityAuditPublisher auditPublisher;

    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private User admin;
    private User target;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        admin = userRepository.save(new User("admin@stampede.io", passwordEncoder.encode("password123"), Role.ADMIN));
        target = userRepository.save(new User("target@stampede.io", passwordEncoder.encode("password123"), Role.USER));
    }

    @Test
    void adminToken_changesTheRole_andTheAuditEventNamesTheAdmin() throws Exception {
        HttpResponse<String> res = putRole(tokenFor(admin.getEmail(), "ADMIN"), "ORGANIZER");

        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains("\"role\":\"ORGANIZER\"");
        assertThat(userRepository.findById(target.getId()).orElseThrow().getRole()).isEqualTo(Role.ORGANIZER);
        ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditPublisher).publish(event.capture());
        assertThat(event.getValue()).isInstanceOfSatisfying(AuditEvent.RoleChanged.class,
                e -> assertThat(e.changedBy()).isEqualTo(admin.getId()));
    }

    @Test
    void userToken_isForbidden_notRedirectedToLogin() throws Exception {
        HttpResponse<String> res = putRole(tokenFor(target.getEmail(), "USER"), "ADMIN");

        assertThat(res.statusCode()).isEqualTo(403);
        assertThat(userRepository.findById(target.getId()).orElseThrow().getRole()).isEqualTo(Role.USER);
        verify(auditPublisher, never()).publish(any());
    }

    @Test
    void noToken_isUnauthorized() throws Exception {
        assertThat(putRole(null, "ADMIN").statusCode()).isEqualTo(401);
    }

    @Test
    void registerStaysPublic() throws Exception {
        HttpResponse<String> res = client.send(HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:" + port + "/api/v1/users/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "{\"email\":\"new@stampede.io\",\"password\":\"password123\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode()).isEqualTo(201);
    }

    /** Signed with identity's own key, shaped like the tokens it issues (sub = email, roles claim). */
    private String tokenFor(String email, String role) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:" + port)
                .subject(email)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("roles", List.of(role))
                .build();
        return new NimbusJwtEncoder(jwkSource).encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private HttpResponse<String> putRole(String token, String role) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + target.getId() + "/role"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"role\":\"" + role + "\"}"));
        if (token != null) {
            req.header("Authorization", "Bearer " + token);
        }
        return client.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }
}

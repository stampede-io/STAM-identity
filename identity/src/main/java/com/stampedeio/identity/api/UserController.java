package com.stampedeio.identity.api;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.stampedeio.identity.api.dto.RegisterRequest;
import com.stampedeio.identity.api.dto.RoleChangeRequest;
import com.stampedeio.identity.api.dto.UserResponse;
import com.stampedeio.identity.audit.AuditEvent;
import com.stampedeio.identity.audit.IdentityAuditPublisher;
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final IdentityAuditPublisher auditPublisher;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder,
                          IdentityAuditPublisher auditPublisher) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditPublisher = auditPublisher;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.status(409).build();
        }

        User user = new User(
                request.email(),
                passwordEncoder.encode(request.password()),
                Role.USER
        );
        user = userRepository.save(user);

        UserResponse response = new UserResponse(user.getId(), user.getEmail(), user.getRole().name());
        return ResponseEntity.created(URI.create("/api/v1/users/" + user.getId())).body(response);
    }

    @PutMapping("/{id}/role")
    public ResponseEntity<UserResponse> changeRole(@PathVariable UUID id,
                                                    @Valid @RequestBody RoleChangeRequest request,
                                                    @AuthenticationPrincipal UserDetails admin) {
        User target = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + id));

        String oldRole = target.getRole().name();
        target.setRole(request.role());
        target = userRepository.save(target);

        UUID adminId = userRepository.findByEmail(admin.getUsername())
                .map(User::getId)
                .orElse(null);

        auditPublisher.publish(new AuditEvent.RoleChanged(
                target.getId(),
                adminId,
                oldRole,
                request.role().name(),
                Instant.now()
        ));

        return ResponseEntity.ok(new UserResponse(target.getId(), target.getEmail(), target.getRole().name()));
    }
}

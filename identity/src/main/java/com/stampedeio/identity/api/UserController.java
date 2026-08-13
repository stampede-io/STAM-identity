package com.stampedeio.identity.api;

import java.net.URI;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.stampedeio.identity.api.dto.RegisterRequest;
import com.stampedeio.identity.api.dto.UserResponse;
import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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
}

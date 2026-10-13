package com.stampedeio.identity.seed;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.stampedeio.identity.domain.Role;
import com.stampedeio.identity.domain.User;
import com.stampedeio.identity.domain.UserRepository;

// STAM-60: demo accounts a recruiter can log in with, no registration
// needed. Runs on every boot but only inserts if missing — the nightly
// demo-reset CronJob truncates identity_db and restarts this pod, so
// this is also what recreates the accounts after a reset (AC2.3), not
// just first boot.
@Component
public class DemoUserSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoUserSeeder.class);
    private static final String DEMO_PASSWORD = "Demo2026!";

    private final boolean demoMode;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public DemoUserSeeder(@Value("${demo.mode:false}") boolean demoMode,
            UserRepository users, PasswordEncoder passwordEncoder) {
        this.demoMode = demoMode;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (!demoMode) {
            return;
        }
        seed("user@demo.local", Role.USER);
        seed("organizer@demo.local", Role.ORGANIZER);
    }

    private void seed(String email, Role role) {
        if (users.existsByEmail(email)) {
            log.info("Demo account already present: {}", email);
            return;
        }
        users.save(new User(email, passwordEncoder.encode(DEMO_PASSWORD), role));
        log.info("Demo account seeded: {} ({})", email, role);
    }
}

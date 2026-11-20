package com.stampedeio.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.stampedeio.identity.domain.UserRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(3)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // STAM-453: CSRF stays on for the session-cookie form login,
                // or a hostile page can POST the attacker's credentials to
                // /login and sign the victim's browser in as the attacker.
                // /api/** is JSON the SPA sends through the gateway (register,
                // role change): no form, and the gateway's CORS policy already
                // blocks cross-origin JSON, so the token doesn't apply there.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll()
                        // Boot forwards errors (e.g. a CSRF 403) to /error;
                        // without this an anonymous caller gets a 302 to
                        // /login instead of the real status.
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/users/register").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/api/v1/users/*/role").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(UserRepository userRepository) {
        return email -> userRepository.findByEmail(email)
                .map(user -> org.springframework.security.core.userdetails.User.builder()
                        .username(user.getEmail())
                        .password(user.getPasswordHash())
                        .roles(user.getRole().name())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
    }
}

package com.stampedeio.identity.seed;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.stampedeio.identity.domain.UserRepository;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DemoUserSeederTest {

    @Test
    void doesNothingWhenDemoModeDisabled() {
        UserRepository users = Mockito.mock(UserRepository.class);
        PasswordEncoder encoder = Mockito.mock(PasswordEncoder.class);
        new DemoUserSeeder(false, users, encoder).run();

        verify(users, never()).save(Mockito.any());
    }

    @Test
    void seedsBothDemoAccountsWhenMissing() {
        UserRepository users = Mockito.mock(UserRepository.class);
        PasswordEncoder encoder = Mockito.mock(PasswordEncoder.class);
        when(users.existsByEmail(anyString())).thenReturn(false);
        when(encoder.encode(anyString())).thenReturn("hashed");

        new DemoUserSeeder(true, users, encoder).run();

        verify(users, times(2)).save(Mockito.any());
    }

    @Test
    void skipsAccountsThatAlreadyExist() {
        UserRepository users = Mockito.mock(UserRepository.class);
        PasswordEncoder encoder = Mockito.mock(PasswordEncoder.class);
        when(users.existsByEmail(anyString())).thenReturn(true);

        new DemoUserSeeder(true, users, encoder).run();

        verify(users, never()).save(Mockito.any());
    }
}

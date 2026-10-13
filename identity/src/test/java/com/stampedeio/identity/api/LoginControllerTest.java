package com.stampedeio.identity.api;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class LoginControllerTest {

    @Test
    void demoCredsHiddenByDefault() {
        LoginController controller = new LoginController();
        ReflectionTestUtils.setField(controller, "demoMode", false);

        assertThat(controller.loginPage()).doesNotContain("Demo2026!");
    }

    @Test
    void demoCredsShownWhenDemoModeEnabled() {
        LoginController controller = new LoginController();
        ReflectionTestUtils.setField(controller, "demoMode", true);

        String page = controller.loginPage();
        assertThat(page)
                .contains("user@demo.local / Demo2026!")
                .contains("organizer@demo.local / Demo2026!");
    }
}

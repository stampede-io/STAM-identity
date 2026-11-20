package com.stampedeio.identity.api;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class LoginControllerTest {

    private static final CsrfToken CSRF = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "tok\"<en>");

    @Test
    void demoCredsHiddenByDefault() {
        LoginController controller = new LoginController();
        ReflectionTestUtils.setField(controller, "demoMode", false);

        assertThat(controller.loginPage(CSRF)).doesNotContain("Demo2026!");
    }

    @Test
    void demoCredsShownWhenDemoModeEnabled() {
        LoginController controller = new LoginController();
        ReflectionTestUtils.setField(controller, "demoMode", true);

        String page = controller.loginPage(CSRF);
        assertThat(page)
                .contains("user@demo.local / Demo2026!")
                .contains("organizer@demo.local / Demo2026!");
    }

    @Test
    void formCarriesTheCsrfTokenHtmlEscaped() {
        // STAM-453: the token is what makes a cross-site login POST fail.
        LoginController controller = new LoginController();
        ReflectionTestUtils.setField(controller, "demoMode", false);

        assertThat(controller.loginPage(CSRF))
                .contains("<input type=\"hidden\" name=\"_csrf\" value=\"tok&quot;&lt;en&gt;\"/>");
    }
}

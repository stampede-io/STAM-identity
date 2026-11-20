package com.stampedeio.identity;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Test helper: the hidden CSRF field identity's login form carries (STAM-453). */
final class LoginPage {

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\s+value=\"([^\"]+)\"");

    private LoginPage() {
    }

    /** {@code &_csrf=<token>}, ready to append to a form-encoded login body. */
    static String csrfParam(String loginPageHtml) {
        Matcher m = CSRF.matcher(loginPageHtml);
        if (!m.find()) {
            throw new AssertionError("login page has no _csrf field:\n" + loginPageHtml);
        }
        return "&_csrf=" + URLEncoder.encode(m.group(1), StandardCharsets.UTF_8);
    }
}

package com.stampedeio.identity.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {

    @Value("${demo.mode:false}")
    private boolean demoMode;

    @GetMapping("/login")
    @ResponseBody
    public String loginPage() {
        // STAM-60 / AC1: the real login form lives here, server-rendered by
        // identity (SecurityConfig's formLogin().loginPage("/login")) — the
        // React SPA never renders its own login UI, it only handles the
        // post-auth redirect (ADR-0005). DEMO_MODE=true is what a recruiter
        // visiting the public demo URL actually sees.
        String demoCreds = demoMode ? """
                <div style="margin-top:1em;padding:0.75em;border:1px solid #ccc;background:#f5f5f5">
                  <strong>Demo mode</strong> — try it without registering:<br/>
                  user@demo.local / Demo2026!<br/>
                  organizer@demo.local / Demo2026!
                </div>
                """ : "";
        return """
                <!DOCTYPE html>
                <html>
                <head><title>STAMPEDE Login</title></head>
                <body>
                <h2>Login</h2>
                <form method="post" action="/login">
                  <label>Email: <input type="email" name="username" required/></label><br/><br/>
                  <label>Password: <input type="password" name="password" required/></label><br/><br/>
                  <button type="submit">Log in</button>
                </form>
                %s
                </body>
                </html>
                """.formatted(demoCreds);
    }
}

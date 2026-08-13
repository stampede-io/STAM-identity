package com.stampedeio.identity.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {

    @GetMapping("/login")
    @ResponseBody
    public String loginPage() {
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
                </body>
                </html>
                """;
    }
}

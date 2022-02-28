package no.nav.security.token.support.spring.test;

import com.nimbusds.jose.JOSEObjectType;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.token.support.core.api.Unprotected;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/local")
public class MockLoginController {

    private final MockOAuth2Server mockOAuth2Server;

    public MockLoginController(MockOAuth2Server mockOAuth2Server) {
        this.mockOAuth2Server = mockOAuth2Server;
    }

    @Unprotected
    @GetMapping("/cookie")
    public Cookie addCookie(
        @RequestParam(value = "issuerId") String issuerId,
        @RequestParam(value = "audience") String audience,
        @RequestParam(value = "subject", defaultValue = "12345678910") String subject,
        @RequestParam(value = "cookiename", defaultValue = "localhost-idtoken") String cookieName,
        @RequestParam(value = "redirect", required = false) String redirect,
        @RequestParam(value = "expiry", required = false) String expiry,
        HttpServletResponse response
    ) throws IOException {

        String token =
            mockOAuth2Server.issueToken(
                issuerId,
                MockLoginController.class.getSimpleName(),
                new DefaultOAuth2TokenCallback(
                    issuerId,
                    subject,
                    JOSEObjectType.JWT.getType(),
                    List.of(audience),
                    Map.of("acr", "Level4"),
                    expiry != null ? Long.parseLong(expiry) : 3600
                )
            ).serialize();

        return createCookieAndAddToResponse(
            response,
            cookieName,
            token,
            redirect
        );
    }

    @Unprotected
    @PostMapping("/cookie/{issuerId}")
    public Cookie addCookie(
        @PathVariable(value = "issuerId") String issuerId,
        @RequestParam(value = "cookiename", defaultValue = "localhost-idtoken") String cookieName,
        @RequestParam(value = "redirect", required = false) String redirect,
        @RequestBody Map<String, Object> claims,
        HttpServletResponse response
    ) throws IOException {
        String token = mockOAuth2Server.anyToken(
            mockOAuth2Server.issuerUrl(issuerId),
            claims
        ).serialize();

        return createCookieAndAddToResponse(
            response,
            cookieName,
            token,
            redirect
        );
    }

    private Cookie createCookieAndAddToResponse(
        HttpServletResponse response,
        String cookieName,
        String token,
        String redirect
    ) throws IOException {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setDomain("localhost");
        cookie.setPath("/");
        response.addCookie(cookie);
        if (redirect != null) {
            response.sendRedirect(redirect);
            return null;
        }
        return cookie;
    }
}

package no.nav.security.token.support.jaxrs;

import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.filter.JwtTokenValidationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

@ActiveProfiles("protected")
@DirtiesContext
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Config.class)
class ClientFilterTest {

    @LocalServerPort
    private int port;

    private Invocation.Builder request() {

        return ClientBuilder.newClient()
                .register(JwtTokenClientRequestFilter.class)
                .target("http://localhost:" + port)
                .path("echo/token")
                .request();
    }

    @Test
    void that_unprotected_returns_ok_with_valid_token() throws ParseException {

        String token = JwtTokenGenerator.createSignedJWT("12345678911").serialize();
        addTokenToContextHolder(token);
        String returnedToken = request().get().readEntity(String.class);
        assertThat(returnedToken, is(equalTo(token)));
    }

    /**
     * Adds the token to the context holder, so it is available for the
     * {@link JwtTokenClientRequestFilter}. This is basically what the
     * {@link JwtTokenValidationFilter} filter does
     */
    private void addTokenToContextHolder(String token) {
        JaxrsTokenValidationContextHolder.getHolder().setTokenValidationContext(createOidcValidationContext("protected", new JwtToken(token)));
    }

    private static TokenValidationContext createOidcValidationContext(String issuerShortName, JwtToken jwtToken) {
        Map<String, JwtToken> map = new ConcurrentHashMap<>();
        map.put(issuerShortName, jwtToken);
        return new TokenValidationContext(map);
    }
}
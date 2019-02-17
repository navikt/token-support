package no.nav.security.oidc.jaxrs;

import static com.nimbusds.jwt.JWTParser.parse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

import java.text.ParseException;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import no.nav.security.oidc.test.support.JwtTokenGenerator;

@ActiveProfiles("protected")
@DirtiesContext
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Config.class)
public class ClientFilterTest {

    @LocalServerPort
    private int port;

    private Invocation.Builder request() {

        return ClientBuilder.newClient()
                .register(OidcClientRequestFilter.class)
                .target("http://localhost:" + port)
                .path("echo/token")
                .request();
    }

    @Test
    public void that_unprotected_returns_ok_with_valid_token() throws ParseException {

        String token = JwtTokenGenerator.createSignedJWT("12345678911").serialize();

        addTokenToContextHolder(token);

        String returnedToken = request().get().readEntity(String.class);

        assertThat(returnedToken, is(equalTo(token)));
    }

    /**
     * Adds the token to the context holder, so it is available for the
     * {@link OidcClientRequestFilter}. This is basically what the
     * {@link no.nav.security.oidc.filter.OIDCTokenValidationFilter} filter does
     */
    private void addTokenToContextHolder(String token) throws ParseException {

        TokenContext tokenContext = new TokenContext("protected", token);
        OIDCValidationContext validationContext = new OIDCValidationContext();
        validationContext.addValidatedToken(tokenContext.getIssuer(), tokenContext,
                new OIDCClaims(parse(tokenContext.getIdToken())));

        OidcRequestContext.getHolder().setOIDCValidationContext(validationContext);
    }
}

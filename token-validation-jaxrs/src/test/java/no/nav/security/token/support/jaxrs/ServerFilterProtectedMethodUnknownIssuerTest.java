package no.nav.security.token.support.jaxrs;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import no.nav.security.token.support.core.JwtTokenConstants;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

@ActiveProfiles("invalid")
@DirtiesContext
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Config.class)
public class ServerFilterProtectedMethodUnknownIssuerTest {

    @LocalServerPort
    private int port;

    private Invocation.Builder requestWithInvalidClaimsToken(String path) {
        return ClientBuilder.newClient().target("http://localhost:" + port)
                .path(path)
                .request()
                .header(JwtTokenConstants.AUTHORIZATION_HEADER,
                        "Bearer " + JwtTokenGenerator.createSignedJWT("12345678911").serialize());
    }

    @Test
    public void that_unprotected_returns_ok_with_invalid_token() {

        Response response = requestWithInvalidClaimsToken("unprotected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_returns_200_with_any_token() {

        Response response = requestWithInvalidClaimsToken("protected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_with_claims_returns_401_with_invalid_token() {

        Response response = requestWithInvalidClaimsToken("protected/with/claims").get();

        assertThat(response.getStatus(), is(equalTo(401)));
    }

}

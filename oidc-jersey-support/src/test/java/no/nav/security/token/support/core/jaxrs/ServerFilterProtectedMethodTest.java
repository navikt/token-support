package no.nav.security.token.support.core.jaxrs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;

import no.nav.security.token.support.core.JwtTokenConstants;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import no.nav.security.token.support.core.test.support.JwtTokenGenerator;

@ActiveProfiles("protected")
@DirtiesContext
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Config.class)
public class ServerFilterProtectedMethodTest {

    @LocalServerPort
    private int port;

    private Invocation.Builder requestWithValidToken(String path) {
        return ClientBuilder.newClient().target("http://localhost:" + port)
                .path(path)
                .request()
                .header(JwtTokenConstants.AUTHORIZATION_HEADER,
                        "Bearer " + JwtTokenGenerator.createSignedJWT("12345678911").serialize());
    }

    private Invocation.Builder requestWithoutToken(String path) {
        return ClientBuilder.newClient().target("http://localhost:" + port)
                .path(path)
                .request();
    }

    @Test
    public void that_unprotected_returns_ok_with_valid_token() {

        Response response = requestWithValidToken("unprotected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_returns_200_with_valid_token() {

        Response response = requestWithValidToken("protected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_with_claims_returns_200_with_valid_token() {

        Response response = requestWithValidToken("protected/with/claims").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_unprotected_returns_200_without_token() {

        Response response = requestWithoutToken("unprotected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_returns_401_without_token() {

        Response response = requestWithoutToken("protected").get();

        assertThat(response.getStatus(), is(equalTo(401)));
    }

    @Test
    public void that_protected_with_claims_returns_401_without_token() {

        Response response = requestWithoutToken("protected/with/claims").get();

        assertThat(response.getStatus(), is(equalTo(401)));
    }

    @Test
    public void that_protected_with_claims_returns_403_with_invalid_claims() {

        Response response = requestWithValidToken("protected/with/claims/unknown").get();

        assertThat(response.getStatus(), is(equalTo(403)));
    }

}

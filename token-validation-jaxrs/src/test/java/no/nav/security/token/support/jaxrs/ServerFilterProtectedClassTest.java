package no.nav.security.token.support.jaxrs;

import no.nav.security.token.support.core.JwtTokenConstants;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

@ActiveProfiles("protected")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = Config.class)
 class ServerFilterProtectedClassTest {

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
    void that_unprotected_returns_ok_with_valid_token() {
        Response response = requestWithValidToken("class/unprotected").get();
        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    void that_protected_returns_200_with_valid_token() {
        Response response = requestWithValidToken("class/protected").get();
        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    void that_protected_with_claims_returns_200_with_valid_token() {
        Response response = requestWithValidToken("class/protected/with/claims").get();
        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    void that_unprotected_returns_200_without_token() {
        Response response = requestWithoutToken("class/unprotected").get();
        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    void that_protected_returns_401_without_token() {
        Response response = requestWithoutToken("class/protected").get();
        assertThat(response.getStatus(), is(equalTo(401)));
    }

    @Test
    void that_protected_with_claims_returns_401_without_token() {
        Response response = requestWithoutToken("class/protected/with/claims").get();
        assertThat(response.getStatus(), is(equalTo(401)));
    }

    @Test
    void that_class_without_annotations_returns_401_with_filter() {
        Response response = requestWithoutToken("without/annotations").get();
        assertThat(response.getStatus(), is(equalTo(401)));
    }

}

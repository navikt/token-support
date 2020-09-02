package no.nav.security.token.support.client.core;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import static no.nav.security.token.support.client.core.TestUtils.jsonResponse;
import static no.nav.security.token.support.client.core.TestUtils.withMockServer;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ClientPropertiesTest {

    private String wellKnownJson =
        "{\n" +
            "  \"issuer\" : \"https://someissuer\",\n" +
            "  \"token_endpoint\" : \"https://someissuer/token\",\n" +
            "  \"jwks_uri\" : \"https://someissuer/jwks\",\n" +
            "  \"grant_types_supported\" : [ \"urn:ietf:params:oauth:grant-type:token-exchange\" ],\n" +
            "  \"token_endpoint_auth_methods_supported\" : [ \"private_key_jwt\" ],\n" +
            "  \"token_endpoint_auth_signing_alg_values_supported\" : [ \"RS256\" ],\n" +
            "  \"subject_types_supported\" : [ \"public\" ]\n" +
            "}";

    private static ClientProperties clientPropertiesFromWellKnown(URI wellKnownUrl) {
        return new ClientProperties(
            null,
            wellKnownUrl,
            OAuth2GrantType.CLIENT_CREDENTIALS,
            List.of("scope1", "scope2"),
            clientAuth(),
            null,
            tokenExchange()
        );
    }

    private static ClientAuthenticationProperties clientAuth() {
        return new ClientAuthenticationProperties(
            "client",
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
            "secret",
            null);
    }

    private static ClientProperties.TokenExchangeProperties tokenExchange() {
        return new ClientProperties.TokenExchangeProperties(
            "aud1",
            null
        );
    }

    private static ClientProperties clientPropertiesFromGrantType(OAuth2GrantType grantType) {
        return new ClientProperties(
            URI.create("http://token"),
            null,
            grantType,
            List.of("scope1", "scope2"),
            clientAuth(),
            null,
            tokenExchange()
        );
    }

    @Test
    void validGrantTypes() {
        clientPropertiesFromGrantType(OAuth2GrantType.JWT_BEARER);
        clientPropertiesFromGrantType(OAuth2GrantType.CLIENT_CREDENTIALS);
        clientPropertiesFromGrantType(OAuth2GrantType.TOKEN_EXCHANGE);
    }

    @Test
    void invalidGrantTypes() {
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> clientPropertiesFromGrantType(new OAuth2GrantType("somegrantNotSupported")));
    }

    @Test
    void ifWellKnownUrlIsNotNullShouldRetrieveMetadataAndSetTokenEndpoint() throws IOException {
        withMockServer(
            s -> {
                s.enqueue(jsonResponse(wellKnownJson));
                clientPropertiesFromWellKnown(s.url("/well-known").uri());
            }
        );
    }

    @Test
    void incorrectWellKnownUrlShouldThrowException(){
        assertThatExceptionOfType(OAuth2ClientException.class)
            .isThrownBy(() ->
                clientPropertiesFromWellKnown(URI.create("http://localhost:1234/notfound"))
            );
    }
}

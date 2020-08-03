package no.nav.security.token.support.client.core;


import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ClientPropertiesTest {

    @Test
    void validAuthenticationProperties() {
        createInstanceWith(OAuth2GrantType.JWT_BEARER);
        createInstanceWith(OAuth2GrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void invalidAuthenticationProperties() {
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> createInstanceWith(new OAuth2GrantType("somegrantNotSupported")));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> ClientProperties.builder()
                .grantType(new OAuth2GrantType("somegrantNotSupported"))
                .build());
    }

    private static void createInstanceWith(OAuth2GrantType grantType) {
        new ClientProperties(
            URI.create("http://token"),
            grantType,
            List.of("scope1", "scope2"),
            new ClientAuthenticationProperties(
                "client",
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                "secret",
                null),
            null,
            new ClientProperties.TokenExchangeProperties(
                "",
                ""
            )
        );
    }
}

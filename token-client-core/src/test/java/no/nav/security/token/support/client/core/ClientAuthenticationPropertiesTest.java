package no.nav.security.token.support.client.core;


import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ClientAuthenticationPropertiesTest {

    @Test
    void validAuthenticationProperties() {
        new ClientAuthenticationProperties(
            "client",
            null,
            "secret",
            null);
        new ClientAuthenticationProperties(
            "client",
            ClientAuthenticationMethod.CLIENT_SECRET_POST,
            "secret",
            null);
    }

    @Test
    void invalidAuthenticationProperties() {
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.TLS_CLIENT_AUTH));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.CLIENT_SECRET_JWT));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.NONE));

        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> ClientAuthenticationProperties.builder()
                .clientAuthMethod(ClientAuthenticationMethod.NONE)
                .build());
    }

    private static void instanceWith(ClientAuthenticationMethod clientAuthenticationMethod) {
        new ClientAuthenticationProperties(
            "client",
            clientAuthenticationMethod,
            "secret",
            null);
    }

}

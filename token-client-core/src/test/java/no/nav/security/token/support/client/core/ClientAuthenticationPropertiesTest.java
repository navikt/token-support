package no.nav.security.token.support.client.core;


import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ClientAuthenticationPropertiesTest {

    @Test
    void invalidAuthenticationProperties() {
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.TLS_CLIENT_AUTH));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(ClientAuthenticationMethod.CLIENT_SECRET_JWT));
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> instanceWith(NONE));

        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> ClientAuthenticationProperties.builder("client1", NONE)
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
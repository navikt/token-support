package no.nav.security.token.support.client.core;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ExchangePropertiesTest {

    @Test
    void validAuthenticationProperties() {
        createInstanceWith(ClientAuthenticationMethod.PRIVATE_KEY_JWT, TestUtils.jwt("sub").serialize(), "");
    }

    @Test
    void invalidAuthenticationProperties() {
        assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> createInstanceWith(ClientAuthenticationMethod.CLIENT_SECRET_JWT, "", ""));
        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> createInstanceWith(ClientAuthenticationMethod.PRIVATE_KEY_JWT, "", null));
    }

    private static void createInstanceWith(ClientAuthenticationMethod authenticationMethod, String subjectToken, String audience) {
        new ExchangeProperties(authenticationMethod,
            audience,
            "",
            TestUtils.jwt("somesub").serialize()
        );
    }
}

package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder

internal class ClientAuthenticationPropertiesTest {

    @Test
    fun invalidAuthenticationProperties() {
        Assertions.assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(ClientAuthenticationMethod.TLS_CLIENT_AUTH) }
        Assertions.assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH) }
        Assertions.assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(ClientAuthenticationMethod.CLIENT_SECRET_JWT) }
        Assertions.assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(ClientAuthenticationMethod.NONE) }
        Assertions.assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy {
                builder("client1", ClientAuthenticationMethod.NONE)
                    .build()
            }
    }

    companion object {

        private fun instanceWith(clientAuthenticationMethod : ClientAuthenticationMethod) {
            ClientAuthenticationProperties(
                "client",
                clientAuthenticationMethod,
                "secret",
                null)
        }
    }
}
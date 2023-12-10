package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder

internal class ClientAuthenticationPropertiesTest {

    @Test
    fun invalidAuthenticationProperties() {
        assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(TLS_CLIENT_AUTH) }
        assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(SELF_SIGNED_TLS_CLIENT_AUTH) }
        assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(CLIENT_SECRET_JWT) }
        assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy { instanceWith(NONE) }
        assertThatExceptionOfType(IllegalArgumentException::class.java)
            .isThrownBy {
                builder("client1", NONE)
                    .build()
            }
    }

    companion object {

        private fun instanceWith(clientAuthenticationMethod : ClientAuthenticationMethod) {
            ClientAuthenticationProperties("client", clientAuthenticationMethod, "secret",
                null)
        }
    }
}
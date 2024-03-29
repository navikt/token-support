package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.TLS_CLIENT_AUTH
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

internal class ClientAuthenticationPropertiesTest {

    @Test
    fun invalidAuthenticationProperties() {
        assertThrows<IllegalArgumentException> { instanceWith(TLS_CLIENT_AUTH) }
        assertThrows<IllegalArgumentException> { instanceWith(SELF_SIGNED_TLS_CLIENT_AUTH) }
        assertThrows<IllegalArgumentException> { instanceWith(CLIENT_SECRET_JWT) }
        assertThrows<IllegalArgumentException> { instanceWith(NONE) }
        assertThrows<IllegalArgumentException> {  builder("client1", NONE).build() }
    }

    private fun instanceWith(clientAuthenticationMethod : ClientAuthenticationMethod) =
        ClientAuthenticationProperties("client", clientAuthenticationMethod, "secret",
            null)

}
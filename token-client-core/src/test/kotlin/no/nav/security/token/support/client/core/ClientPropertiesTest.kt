package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.io.IOException
import java.net.URI
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.withMockServer

internal class ClientPropertiesTest {

    private val wellKnownJson = """
          {
            "issuer" : "https://someissuer",
            "token_endpoint" : "https://someissuer/token",
            "jwks_uri" : "https://someissuer/jwks",
            "grant_types_supported" : [ "urn:ietf:params:oauth:grant-type:token-exchange" ],
            "token_endpoint_auth_methods_supported" : [ "private_key_jwt" ],
            "token_endpoint_auth_signing_alg_values_supported" : [ "RS256" ],
            "subject_types_supported" : [ "public" ]
          }
          """.trimIndent()

    @Test
    fun validGrantTypes() {
        assertNotNull(clientPropertiesFromGrantType(JWT_BEARER))
        assertNotNull(clientPropertiesFromGrantType(CLIENT_CREDENTIALS))
        assertNotNull(clientPropertiesFromGrantType(TOKEN_EXCHANGE))
    }

    @Test
    @Throws(IOException::class)
    fun ifWellKnownUrlIsNotNullShouldRetrieveMetadataAndSetTokenEndpoint() {
        withMockServer {
            it.enqueue(jsonResponse(wellKnownJson))
            assertNotNull(clientPropertiesFromWellKnown(it.url("/well-known").toUri()).tokenEndpointUrl)
        }
    }

    @Test
    fun incorrectWellKnownUrlShouldThrowException() {
        assertThatExceptionOfType(OAuth2ClientException::class.java)
            .isThrownBy { clientPropertiesFromWellKnown(URI.create("http://localhost:1234/notfound")) }
    }

    companion object {

        private fun clientPropertiesFromWellKnown(wellKnownUrl : URI) : ClientProperties {
            return ClientProperties(
                null,
                wellKnownUrl,
                CLIENT_CREDENTIALS, listOf("scope1", "scope2"),
                clientAuth(),
                null,
                tokenExchange())
        }

        private fun clientAuth() : ClientAuthenticationProperties {
            return ClientAuthenticationProperties(
                "client",
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                "secret", null)
        }

        private fun tokenExchange() : TokenExchangeProperties {
            return TokenExchangeProperties(
                "aud1",
                null)
        }

        private fun clientPropertiesFromGrantType(grantType : GrantType) : ClientProperties {
            return ClientProperties(
                URI.create("http://token"),
                null,
                grantType, listOf("scope1", "scope2"),
                clientAuth(),
                null,
                tokenExchange())
        }
    }
}
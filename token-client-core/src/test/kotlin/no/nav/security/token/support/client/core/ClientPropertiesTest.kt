package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import no.nav.security.token.support.client.core.ClientProperties.ClientPropertiesBuilder
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
    fun ifWellKnownUrlIsNotNullShouldRetrieveMetadataAndSetTokenEndpoint() {
        withMockServer {
            it.enqueue(jsonResponse(wellKnownJson))
            assertNotNull(clientPropertiesFromWellKnown(it.url("/well-known").toString()).tokenEndpointUrl)
        }
    }

    @Test
    fun incorrectWellKnownUrlShouldThrowException() {
        assertThrows<OAuth2ClientException> { clientPropertiesFromWellKnown("http://localhost:1234/notfound")}
    }


    private fun clientPropertiesFromWellKnown(wellKnownUrl : String) =
        ClientPropertiesBuilder(CLIENT_CREDENTIALS,clientAuth())
            .wellKnownUrl(wellKnownUrl)
            .scopes("scope1", "scope2")
            .tokenExchange(tokenExchange())
            .build()

    private fun clientPropertiesFromGrantType(grantType : GrantType) =
        ClientPropertiesBuilder(grantType, clientAuth())
            .tokenEndpointUrl("http://token")
            .scopes("scope1", "scope2")
            .tokenExchange(tokenExchange())
            .build()

    private fun clientAuth() =
        ClientAuthenticationPropertiesBuilder("client",CLIENT_SECRET_BASIC)
            .clientSecret("secret")
            .build()
    private fun tokenExchange() = TokenExchangeProperties("aud1")


}
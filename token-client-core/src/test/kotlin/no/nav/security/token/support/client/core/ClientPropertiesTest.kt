package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import no.nav.security.token.support.client.core.ClientProperties.ClientPropertiesBuilder
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.withMockServer

internal class ClientPropertiesTest : BehaviorSpec({

    Given("valid grant types") {
        When("creating client properties") {
            Then("should create valid properties for JWT_BEARER") {
                clientPropertiesFromGrantType(JWT_BEARER).shouldNotBeNull()
            }
            Then("should create valid properties for CLIENT_CREDENTIALS") {
                clientPropertiesFromGrantType(CLIENT_CREDENTIALS).shouldNotBeNull()
            }
            Then("should create valid properties for TOKEN_EXCHANGE") {
                clientPropertiesFromGrantType(TOKEN_EXCHANGE).shouldNotBeNull()
            }
        }
    }

    Given("a well-known URL is provided") {
        When("retrieving metadata") {
            Then("should set the token endpoint URL") {
                withMockServer {
                    it.enqueue(jsonResponse(wellKnownJson))
                    clientPropertiesFromWellKnown(it.url("/well-known").toString()).tokenEndpointUrl.shouldNotBeNull()
                }
            }
        }
    }

    Given("an incorrect well-known URL") {
        When("retrieving metadata") {
            Then("should throw OAuth2ClientException") {
                shouldThrow<OAuth2ClientException> {
                    clientPropertiesFromWellKnown("http://localhost:1234/notfound")
                }
            }
        }
    }

}) {
    companion object {
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

        private fun clientAuth() =
            ClientAuthenticationPropertiesBuilder("client", CLIENT_SECRET_BASIC)
                .clientSecret("secret")
                .build()

        private fun tokenExchange() = TokenExchangeProperties("aud1")

        fun clientPropertiesFromWellKnown(wellKnownUrl: String) =
            ClientPropertiesBuilder(CLIENT_CREDENTIALS, clientAuth())
                .wellKnownUrl(wellKnownUrl)
                .scopes("scope1", "scope2")
                .tokenExchange(tokenExchange())
                .build()

        fun clientPropertiesFromGrantType(grantType: GrantType) =
            ClientPropertiesBuilder(grantType, clientAuth())
                .tokenEndpointUrl("http://token")
                .scopes("scope1", "scope2")
                .tokenExchange(tokenExchange())
                .build()
    }
}

package no.nav.security.token.support.ktor

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.nimbusds.jwt.JWTClaimNames.AUDIENCE
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import io.kotest.assertions.asClue
import io.kotest.assertions.assertSoftly
import io.kotest.matchers.shouldBe
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.serialization.jackson.jackson
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.withMockOAuth2Server
import no.nav.security.token.support.client.core.jwk.JwkFactory
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER

internal class ApplicationTest {

    @Test
    @DisplayName("HTTP GET to client_credentials, tokenx and obo should trigger token client and return claims in response")
    fun flows() =
        withMockOAuth2Server {
            val token = issueToken("issuer1", "foo", "aud1")
            testApplication {
                environment {
                    config = configure(this@withMockOAuth2Server, "issuer1", "aud1")
                    module {
                      module()
                   }
                }
                val client = createClient {
                    install(ContentNegotiation) {
                        jackson {
                            configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
                        }
                    }
                }
                assertSoftly {
                    client.get("/client_credentials") {
                    }.body<DemoTokenResponse>().asClue {
                        it.claims[SUBJECT] shouldBe "client1"
                        it.claims[AUDIENCE] shouldBe listOf("targetscope")
                    }
                }
                assertSoftly {
                    client.get("/onbehalfof") {
                        header(AUTHORIZATION_HEADER, "Bearer ${token.serialize()}")
                    }.body<DemoTokenResponse>().asClue {
                        it.claims[SUBJECT] shouldBe "foo"
                        it.claims[AUDIENCE] shouldBe listOf("targetscope")
                    }
                }
                assertSoftly {
                    client.get("/tokenx") {
                        header(AUTHORIZATION_HEADER, "Bearer ${token.serialize()}")
                    }.body<DemoTokenResponse>().asClue {
                        it.claims[SUBJECT] shouldBe "foo"
                        it.claims[AUDIENCE] shouldBe listOf("targetaudience")
                    }
                }
            }
        }



    private fun configure(server : MockOAuth2Server, issuerId : String = "issuer1", acceptedAudience : String = "default") =
        MapApplicationConfig().apply {
            val prefix = "no.nav.security.jwt"
            put("$prefix.issuers.size", "1")
            put("$prefix.issuers.0.issuer_name", issuerId)
            put("$prefix.issuers.0.discoveryurl", "${server.wellKnownUrl(issuerId)}")
            put("$prefix.issuers.0.accepted_audience", acceptedAudience)
            put("$prefix.client.registration.clients.size", "1")
            put("$prefix.client.registration.clients.0.client_name", "issuer1")
            put("$prefix.client.registration.clients.0.well_known_url", "${server.wellKnownUrl(issuerId)}")
            put("$prefix.client.registration.clients.0.authentication.client_id", "client1")
            put("$prefix.client.registration.clients.0.authentication.client_auth_method", "private_key_jwt")
            put("$prefix.client.registration.clients.0.authentication.client_jwk", JwkFactory.fromJsonFile("src/main/resources/jwk.json").toJSONString())
        }
}
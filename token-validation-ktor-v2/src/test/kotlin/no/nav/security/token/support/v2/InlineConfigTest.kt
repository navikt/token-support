package no.nav.security.token.support.v2

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.any
import com.github.tomakehurst.wiremock.client.WireMock.configureFor
import com.github.tomakehurst.wiremock.client.WireMock.okJson
import com.github.tomakehurst.wiremock.client.WireMock.stubFor
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import no.nav.security.token.support.v2.inlineconfigtestapp.helloCounter
import no.nav.security.token.support.v2.inlineconfigtestapp.inlineConfiguredModule
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.*
import no.nav.security.token.support.v2.InlineConfigTest.Companion.server
import kotlin.test.assertEquals

class InlineConfigTest {

    companion object {
        val server: WireMockServer = WireMockServer(WireMockConfiguration.options().port(33445))
        @BeforeAll
        @JvmStatic
        fun before() {
            server.start()
            configureFor(server.port())
        }
        @AfterAll
        @JvmStatic
        fun after() {
            server.stop()
        }
    }

    @Test
    fun inlineconfig_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            this.application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }

            val response = client.get("/inlineconfig") {
                val jwt =
                    JwtTokenGenerator.createSignedJWT(buildClaimSet(subject = "testuser", issuer = "someUnknownISsuer"))
                header("Authorization", "Bearer ${jwt.serialize()}")
            }

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals(helloCounterBeforeRequest, helloCounter)

        }
    }

    @Test
    fun inlineconfig_withoutValidJWTinHeaderShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            this.application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }

            val response = client.get("/inlineconfig")

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals(helloCounterBeforeRequest, helloCounter)

        }
    }

    @Test
    fun inlineconfig_withValidJWTinHeaderShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            this.application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }

             val response = client.get("/inlineconfig") {
                 val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                 header("Authorization", "Bearer ${jwt.serialize()}")
             }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
        }
    }

    @Test
    fun inlineconfig_JWTwithAnotherValidAudienceShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            this.application {
            stubOIDCProvider()
            inlineConfiguredModule()
            }
             val response = client.get("/inlineconfig") {
                 val jwt =
                     JwtTokenGenerator.createSignedJWT(buildClaimSet(subject = "testuser", audience = "anotherAudience"))
                 header(HttpHeaders.Authorization, "Bearer ${jwt.serialize()}")
             }

                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)

            }
        }
    }

    @Test
    fun inlineconfig_JWTwithUnknownAudienceShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            this.application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }
            val response = client.get("/inlineconfig") {
                val jwt =
                    JwtTokenGenerator.createSignedJWT(buildClaimSet(subject = "testuser", audience = "unknownAudience"))
                header(HttpHeaders.Authorization, "Bearer ${jwt.serialize()}")
            }

            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals(helloCounterBeforeRequest, helloCounter)
        }
    }

    fun stubOIDCProvider() {
        stubFor(any(urlPathEqualTo("/.well-known/openid-configuration")).willReturn(
            okJson("{\"jwks_uri\": \"${server.baseUrl()}/keys\", " +
                "\"subject_types_supported\": [\"pairwise\"], " +
                "\"issuer\": \"${JwtTokenGenerator.ISS}\"}")))

        stubFor(any(urlPathEqualTo("/keys")).willReturn(
            okJson(JwkGenerator.jWKSet.toPublicJWKSet().toString())))
    }

    fun buildClaimSet(subject: String,
                      issuer: String = JwtTokenGenerator.ISS,
                      audience: String = JwtTokenGenerator.AUD,
                      authLevel: String = JwtTokenGenerator.ACR,
                      expiry: Long = JwtTokenGenerator.EXPIRY,
                      issuedAt: Date = Date(),
                      navIdent: String? = null): JWTClaimsSet {
        val builder = JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .audience(audience)
            .jwtID(UUID.randomUUID().toString())
            .claim("acr", authLevel)
            .claim("ver", "1.0")
            .claim("nonce", "myNonce")
            .claim("auth_time", issuedAt)
            .notBeforeTime(issuedAt)
            .issueTime(issuedAt)
            .expirationTime(Date(issuedAt.time + expiry))
        if (navIdent != null) {
            builder.claim("NAVident", navIdent)
        }
        return builder.build()
    }

package no.nav.security.token.support.v2

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.any
import com.github.tomakehurst.wiremock.client.WireMock.configureFor
import com.github.tomakehurst.wiremock.client.WireMock.okJson
import com.github.tomakehurst.wiremock.client.WireMock.stubFor
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.testing.testApplication
import java.util.Date
import java.util.UUID
import kotlin.test.assertEquals
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.v2.JwkGenerator.jWKSet
import no.nav.security.token.support.v2.JwtTokenGenerator.ACR
import no.nav.security.token.support.v2.JwtTokenGenerator.AUD
import no.nav.security.token.support.v2.JwtTokenGenerator.EXPIRY
import no.nav.security.token.support.v2.JwtTokenGenerator.ISS
import no.nav.security.token.support.v2.JwtTokenGenerator.createSignedJWT
import no.nav.security.token.support.v2.inlineconfigtestapp.helloCounter
import no.nav.security.token.support.v2.inlineconfigtestapp.inlineConfiguredModule

//@Disabled("Skjønner ikke hvorfor den kjører lokalt, men ikke i GHA")
class InlineConfigTest {

    companion object {
        private val logger = LoggerFactory.getLogger(ApplicationTest::class.java)
        val server = WireMockServer(33445)
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
        private fun SignedJWT.asBearer() = "Bearer ${serialize()}"
    }

    @Test
    fun inlineconfig_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication{
            stubOIDCProvider()
            application {
                inlineConfiguredModule()
            }
            val response = client.get("/inlineconfig") {
                header(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet("testuser", "someUnknownISsuer")).asBearer())
            }
            assertEquals(Unauthorized, response.status)
            assertEquals(helloCounterBeforeRequest, helloCounter)
        }
    }

    @Test
    fun inlineconfig_withoutValidJWTinHeaderShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication{
            application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }
            assertEquals(Unauthorized, client.get("/inlineconfig").status)
            assertEquals(helloCounterBeforeRequest, helloCounter)
        }
    }

    @Test
    fun inlineconfig_withValidJWTinHeaderShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }
            val response = client.get("/inlineconfig") {
                header(AUTHORIZATION_HEADER, createSignedJWT("testuser").asBearer())
            }
            assertEquals(OK, response.status)
            assertEquals(helloCounterBeforeRequest + 1, helloCounter)
        }
    }

    @Test
    fun inlineconfig_JWTwithAnotherValidAudienceShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }
            val response = client.get("/inlineconfig") {
                header(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet(subject = "testuser", audience = "anotherAudience")).asBearer())
            }
            assertEquals(OK, response.status)
            assertEquals(helloCounterBeforeRequest + 1, helloCounter)
        }
    }

    @Test
    fun inlineconfig_JWTwithUnknownAudienceShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        testApplication {
            application {
                stubOIDCProvider()
                inlineConfiguredModule()
            }
            val response = client.get("/inlineconfig") {
                header(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet(subject = "testuser", audience = "unknownAudience")).asBearer())
            }
            assertEquals(Unauthorized, response.status)
            assertEquals(helloCounterBeforeRequest, helloCounter)
        }
    }

    fun stubOIDCProvider() {
        stubFor(any(urlPathEqualTo("/.well-known/openid-configuration")).willReturn(okJson("""{"jwks_uri": "${server.baseUrl()}/keys", "subject_types_supported": ["pairwise"], "issuer": "$ISS"}""")))
        stubFor(any(urlPathEqualTo("/keys")).willReturn(okJson(jWKSet.toPublicJWKSet().toString())))
    }

    fun buildClaimSet(subject: String, issuer: String = ISS, audience: String = AUD, authLevel: String = ACR, expiry: Long = EXPIRY, issuedAt: Date = Date(), navIdent: String? = null): JWTClaimsSet {
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
}
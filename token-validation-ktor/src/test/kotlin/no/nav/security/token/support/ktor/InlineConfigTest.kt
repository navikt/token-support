package no.nav.security.token.support.ktor

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.any
import com.github.tomakehurst.wiremock.client.WireMock.configureFor
import com.github.tomakehurst.wiremock.client.WireMock.okJson
import com.github.tomakehurst.wiremock.client.WireMock.stubFor
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import no.nav.security.token.support.ktor.inlineconfigtestapp.helloCounter
import no.nav.security.token.support.ktor.inlineconfigtestapp.inlineConfiguredModule
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.ktor.JwkGenerator.jWKSet
import no.nav.security.token.support.ktor.JwtTokenGenerator.ACR
import no.nav.security.token.support.ktor.JwtTokenGenerator.AUD
import no.nav.security.token.support.ktor.JwtTokenGenerator.EXPIRY
import no.nav.security.token.support.ktor.JwtTokenGenerator.ISS
import no.nav.security.token.support.ktor.JwtTokenGenerator.createSignedJWT

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

        private fun SignedJWT.asBearer() = "Bearer ${serialize()}"

    }

    @Test
    fun inlineconfig_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            inlineConfiguredModule()
        }) {
            handleRequest(HttpMethod.Get, "/inlineconfig") {
                addHeader(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet(subject = "testuser", issuer = "someUnknownISsuer")).asBearer())
            }.apply {
                assertEquals(Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun inlineconfig_withoutValidJWTinHeaderShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            inlineConfiguredModule()
        }) {
            handleRequest(HttpMethod.Get, "/inlineconfig") {
            }.apply {
                assertEquals(Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun inlineconfig_withValidJWTinHeaderShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            inlineConfiguredModule()
        }) {
            handleRequest(HttpMethod.Get, "/inlineconfig") {
                addHeader(AUTHORIZATION_HEADER, createSignedJWT("testuser").asBearer())
            }.apply {
                assertEquals(OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun inlineconfig_JWTwithAnotherValidAudienceShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            inlineConfiguredModule()
        }) {
            handleRequest(HttpMethod.Get, "/inlineconfig") {
                addHeader(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet(subject = "testuser", audience = "anotherAudience")).asBearer())
            }.apply {
                assertEquals(OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun inlineconfig_JWTwithUnknownAudienceShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            inlineConfiguredModule()
        }) {
            handleRequest(HttpMethod.Get, "/inlineconfig") {
                addHeader(AUTHORIZATION_HEADER, createSignedJWT(buildClaimSet(subject = "testuser", audience = "unknownAudience")).asBearer())
            }.apply {
                assertEquals(Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    fun stubOIDCProvider() {
        stubFor(any(urlPathEqualTo("/.well-known/openid-configuration")).willReturn(okJson("""{"jwks_uri": "${server.baseUrl()}/keys", "subject_types_supported": ["pairwise"], "issuer": "$ISS"}""")))
        stubFor(any(urlPathEqualTo("/keys")).willReturn(okJson(jWKSet.toPublicJWKSet().toString())))
    }

    fun buildClaimSet(subject: String,
                      issuer: String = ISS,
                      audience: String = AUD,
                      authLevel: String =ACR,
                      expiry: Long = EXPIRY,
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

}
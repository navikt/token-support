package no.nav.security.token.support.ktor

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.application.Application
import io.ktor.config.MapApplicationConfig
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import no.nav.security.token.support.ktor.testapp.*
import no.nav.security.token.support.test.JwkGenerator
import no.nav.security.token.support.test.JwtTokenGenerator
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals

class ApplicationTest {

    companion object {
        val server: WireMockServer = WireMockServer(WireMockConfiguration.options().dynamicPort())
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

    private val idTokenCookieName = "selvbetjening-idtoken"

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun hello_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT(buildClaimSet(subject = "testuser", issuer = "someUnknownISsuer"))
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun hello_withValidJWTinHeaderShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun hello_withValidJWTinCookieShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun hello_withExpiredJWTinCookieShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser", -1)
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun openhello_withMissingJWTShouldGive_200_andOpenHelloCounterIsIncreased() {
        val openHelloCounterBeforeRequest = openHelloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/openhello") {
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(openHelloCounterBeforeRequest + 1, openHelloCounter)
            }
        }
    }

    @Test
    fun shouldWorkForJWTInHeaderWithhoutCookieConfig() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            stubOIDCProvider()
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }


    //////////////////////////////////////////
    //////////////////////////////////////////
    //////////////////////////////////////////

    fun stubOIDCProvider() {
        stubFor(any(urlPathEqualTo("/.well-known/openid-configuration")).willReturn(
            okJson("{\"jwks_uri\": \"${server.baseUrl()}/keys\", " +
                "\"subject_types_supported\": [\"pairwise\"], " +
                "\"issuer\": \"${JwtTokenGenerator.ISS}\"}")))

        stubFor(any(urlPathEqualTo("/keys")).willReturn(
            okJson(JwkGenerator.getJWKSet().toPublicJWKSet().toString())))
    }

    fun Application.doConfig(acceptedIssuer:String = JwtTokenGenerator.ISS,
                             acceptedAudience:String = JwtTokenGenerator.AUD,
                             hasCookieConfig:Boolean = true) {
        (environment.config as MapApplicationConfig).apply {
            put("no.nav.security.jwt.issuers.size", "1")
            put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
            put("no.nav.security.jwt.issuers.0.discoveryurl", server.baseUrl() + "/.well-known/openid-configuration")
            put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
            if (hasCookieConfig) {
                put("no.nav.security.jwt.issuers.0.cookie_name", idTokenCookieName)
            }
        }
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

}

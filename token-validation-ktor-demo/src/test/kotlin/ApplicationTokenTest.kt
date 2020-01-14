package com.example

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import io.ktor.application.Application
import io.ktor.config.MapApplicationConfig
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.test.JwkGenerator
import no.nav.security.token.support.test.JwtTokenGenerator
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

private const val idTokenCookieName = "selvbetjening-idtoken"

@KtorExperimentalAPI
class ApplicationTokenTest {

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized() {
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module(enableMock = false)
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
            }
        }
    }

    @Test
    fun hello_withValidJWTinHeaderShouldGive_200_OK() {
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module(enableMock = false)
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    @Test
    fun hello_withValidJWTinCookieShouldGive_200_OK() {
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module(enableMock = false)
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = JwtTokenGenerator.createSignedJWT("testuser")
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    @Test
    fun openhello_withMissingJWTShouldGive_200() {
        withTestApplication({
            stubOIDCProvider()
            doConfig()
            module(enableMock = false)
        }) {
            handleRequest(HttpMethod.Get, "/openhello") {
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

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
}

@KtorExperimentalAPI
private fun stubOIDCProvider() {
    stubFor(
        any(urlPathEqualTo("/.well-known/openid-configuration")).willReturn(
            okJson(
                "{\"jwks_uri\": \"${ApplicationTokenTest.server.baseUrl()}/keys\", " +
                    "\"subject_types_supported\": [\"pairwise\"], " +
                    "\"issuer\": \"${JwtTokenGenerator.ISS}\"}"
            )
        )
    )

    stubFor(
        any(urlPathEqualTo("/keys")).willReturn(
            okJson(JwkGenerator.getJWKSet().toPublicJWKSet().toString())
        )
    )
}

@KtorExperimentalAPI
private fun Application.doConfig(
    acceptedIssuer: String = JwtTokenGenerator.ISS,
    acceptedAudience: String = JwtTokenGenerator.AUD
) {
    (environment.config as MapApplicationConfig).apply {
        put("no.nav.security.jwt.issuers.size", "1")
        put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
        put(
            "no.nav.security.jwt.issuers.0.discoveryurl",
            "${ApplicationTokenTest.server.baseUrl()}/.well-known/openid-configuration"
        )
        put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
        put("no.nav.security.jwt.issuers.0.cookie_name", idTokenCookieName)
    }
}

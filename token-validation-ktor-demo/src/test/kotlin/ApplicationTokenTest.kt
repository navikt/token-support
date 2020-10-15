package com.example

import io.ktor.application.Application
import io.ktor.config.MapApplicationConfig
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.TestApplicationEngine
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.mock.oauth2.MockOAuth2Server
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

private const val idTokenCookieName = "selvbetjening-idtoken"

@KtorExperimentalAPI
class ApplicationTokenTest {

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized() {
        withTestApplication {
            with(handleRequest(HttpMethod.Get, "/hello")) {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
            }
        }
    }

    @Test
    fun hello_withInvalidJWTShouldGive_401_Unauthorized() {
        withTestApplication({
            doConfig(
                acceptedAudience = "some-audience",
                acceptedIssuer = "some-issuer"
            )
            module()
        }) {
            with(handleRequest(HttpMethod.Get, "/hello") {
                addHeader("Authorization", "Bearer ${server.issueToken(audience = "not-accepted").serialize()}")
            }) {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
            }

            with(handleRequest(HttpMethod.Get, "/hello") {
                addHeader("Authorization", "Bearer ${server.issueToken(issuerId = "not-accepted").serialize()}")
            }) {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
            }
        }
    }

    @Test
    fun hello_withValidJWTinHeaderShouldGive_200_OK() {
        withTestApplication {
            with(handleRequest(HttpMethod.Get, "/hello") {
                addHeader("Authorization", "Bearer ${server.issueToken().serialize()}")
            }) {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    @Test
    fun hello_withValidJWTinCookieShouldGive_200_OK() {
        withTestApplication {
            with(handleRequest(HttpMethod.Get, "/hello") {
                addHeader("Cookie", "$idTokenCookieName=${server.issueToken().serialize()}")
            }) {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    @Test
    fun openhello_withMissingJWTShouldGive_200() {
        withTestApplication {
            with(handleRequest(HttpMethod.Get, "/openhello")) {
                assertEquals(HttpStatusCode.OK, response.status())
            }
        }
    }

    private fun <R> withTestApplication(test: TestApplicationEngine.() -> R): R {
        return withTestApplication({
            doConfig()
            module()
        }) {
            test()
        }
    }

    private fun Application.doConfig(
        acceptedIssuer: String = "default",
        acceptedAudience: String = "default"
    ) {
        (environment.config as MapApplicationConfig).apply {
            put("no.nav.security.jwt.issuers.size", "1")
            put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
            put("no.nav.security.jwt.issuers.0.discoveryurl", "${server.wellKnownUrl(acceptedIssuer)}")
            put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
            put("no.nav.security.jwt.issuers.0.cookie_name", idTokenCookieName)
        }
    }

    companion object {
        val server = MockOAuth2Server()

        @BeforeAll
        @JvmStatic
        fun before() {
            server.start()

        }

        @AfterAll
        @JvmStatic
        fun after() {
            server.shutdown()
        }
    }
}

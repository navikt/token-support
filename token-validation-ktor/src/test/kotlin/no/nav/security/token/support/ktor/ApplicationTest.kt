package no.nav.security.token.support.ktor

import io.ktor.application.Application
import io.ktor.config.MapApplicationConfig
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.handleRequest
import io.ktor.server.testing.withTestApplication
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.ktor.testapp.helloCounter
import no.nav.security.token.support.ktor.testapp.helloGroupCounter
import no.nav.security.token.support.ktor.testapp.helloPersonCounter
import no.nav.security.token.support.ktor.testapp.module
import no.nav.security.token.support.ktor.testapp.openHelloCounter
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ApplicationTest {

    companion object {
        const val ISSUER_ID = "default"
        const val ACCEPTED_AUDIENCE = "default"

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

    private val idTokenCookieName = "selvbetjening-idtoken"

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
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
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = "unknown", subject = "testuser")
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
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun `token without sub should NOT be accepted if NOT configured as optional claim`() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.anyToken(
                    server.issuerUrl(ISSUER_ID),
                    mapOf("aud" to ACCEPTED_AUDIENCE)
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun `token without sub should be accepted if configured as optional claim`() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            doConfig().apply {
                put("no.nav.security.jwt.issuers.0.validation.optional_claims", "sub")
            }
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.anyToken(
                    server.issuerUrl(ISSUER_ID),
                    mapOf("aud" to ACCEPTED_AUDIENCE)
                )
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
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
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
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser", expiry = -120)
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloCounter)
            }
        }
    }

    @Test
    fun hello_withSoonExpiringJWTinCookieShouldGive_200_OK_andSetTokenExpiresSoonHeader_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloCounter
        withTestApplication({
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser", expiry = 60)
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals("true", response.headers["x-token-expires-soon"])
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    @Test
    fun hello_withoutSoonExpiringJWTinCookieShouldGive_200_OK_andNotSetTokenExpiresSoonHeader() {
        withTestApplication({
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    expiry = Duration.ofMinutes(30).toSeconds()
                )
                addHeader("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertNull(response.headers["x-token-expires-soon"])
            }
        }
    }

    @Test
    fun helloPerson_withMissingRequiredClaimShouldGive_401_andHelloCounterIsNotIncreased() {
        val helloCounterBeforeRequest = helloPersonCounter
        withTestApplication({
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_person") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloCounterBeforeRequest, helloPersonCounter)
            }
        }
    }

    @Test
    fun helloPerson_withRequiredClaimShouldGive_200_OK_andHelloCounterIsIncreased() {
        val helloCounterBeforeRequest = helloPersonCounter
        withTestApplication({
            doConfig()
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_person") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf("NAVident" to "X112233")
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloPersonCounter)
            }
        }
    }


    @Test
    fun openhello_withMissingJWTShouldGive_200_andOpenHelloCounterIsIncreased() {
        val openHelloCounterBeforeRequest = openHelloCounter
        withTestApplication({
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
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloCounterBeforeRequest + 1, helloCounter)
            }
        }
    }

    //// hello_group ////

    @Test
    fun helloGroup_withoutRequiredGroup_ShouldGive_401_OK_andHelloGroupCounterIsNOTIncreased() {
        val helloGroupCounterBeforeRequest = helloGroupCounter
        withTestApplication({
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_group") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf(
                        "NAVident" to "X112233",
                        "groups" to listOf("group1", "group2")
                    )
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloGroupCounterBeforeRequest, helloGroupCounter)
            }
        }
    }

    @Test
    fun helloGroup_withNoGroupClaim_ShouldGive_401_andHelloGroupCounterIsNOTIncreased() {
        val helloGroupCounterBeforeRequest = helloGroupCounter
        withTestApplication({
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_group") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf(
                        "NAVident" to "X112233",
                    )
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloGroupCounterBeforeRequest, helloGroupCounter)
            }
        }
    }

    @Test
    fun helloGroup_withRequiredGroup_ShouldGive_200_OK_andHelloGroupCounterIsIncreased() {
        val helloGroupCounterBeforeRequest = helloGroupCounter
        withTestApplication({
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_group") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf(
                        "NAVident" to "X112233",
                        "groups" to listOf("group1", "group2", "THEGROUP")
                    )
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.OK, response.status())
                assertEquals(helloGroupCounterBeforeRequest + 1, helloGroupCounter)
            }
        }
    }

    @Test
    fun helloGroup_withMissingNAVIdentRequiredForAuditLog_ShouldGive_401_andHelloGroupCounterIsNOTIncreased() {
        val helloGroupCounterBeforeRequest = helloGroupCounter
        withTestApplication({
            doConfig(hasCookieConfig = false)
            module()
        }) {
            handleRequest(HttpMethod.Get, "/hello_group") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf(
                        "groups" to listOf("group1", "group2", "THEGROUP")
                    )
                )
                addHeader("Authorization", "Bearer ${jwt.serialize()}")
            }.apply {
                assertEquals(HttpStatusCode.Unauthorized, response.status())
                assertEquals(helloGroupCounterBeforeRequest, helloGroupCounter)
            }
        }
    }

    private fun Application.doConfig(
        acceptedIssuer: String = ISSUER_ID,
        acceptedAudience: String = ACCEPTED_AUDIENCE,
        hasCookieConfig: Boolean = true
    ): MapApplicationConfig {
        return (environment.config as MapApplicationConfig).apply {
            put("no.nav.security.jwt.expirythreshold", "5")
            put("no.nav.security.jwt.issuers.size", "1")
            put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
            put(
                "no.nav.security.jwt.issuers.0.discoveryurl",
                server.wellKnownUrl(ISSUER_ID).toString()
            )//server.baseUrl() + "/.well-known/openid-configuration")
            put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
            if (hasCookieConfig) {
                put("no.nav.security.jwt.issuers.0.cookie_name", idTokenCookieName)
            }
        }
    }
}
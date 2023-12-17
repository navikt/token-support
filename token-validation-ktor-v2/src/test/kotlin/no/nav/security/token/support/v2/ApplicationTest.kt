package no.nav.security.token.support.v2

import com.nimbusds.jwt.JWTClaimNames.AUDIENCE
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpStatusCode
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.slf4j.LoggerFactory
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.v2.testapp.module

class ApplicationTest {

    private companion object {
        private val logger = LoggerFactory.getLogger(ApplicationTest::class.java)

        const val ISSUER_ID = "default"
        const val ACCEPTED_AUDIENCE = "default"

        val server = MockOAuth2Server()

        @BeforeAll
        @JvmStatic
        fun before() {
            logger.info("Starting up MockOAuth2Server...")
            server.start()
        }

        @AfterAll
        @JvmStatic
        fun after() {
            logger.info("Tearing down MockOAuth2Server...")
            server.shutdown()
        }
    }

    private val idTokenCookieName = "selvbetjening-idtoken"

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun hello_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(issuerId = "unknown", subject = "testuser")
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun hello_withValidJWTinHeaderShouldGive_200_OK_andHelloCounterIsIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `token without sub should NOT be accepted if NOT configured as optional claim`() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.anyToken(
                server.issuerUrl(ISSUER_ID),
                mapOf(AUDIENCE to ACCEPTED_AUDIENCE)
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token without sub should be accepted if configured as optional claim`() = testApplication {
        environment {
            config = doConfig().apply {
                put("no.nav.security.jwt.issuers.0.validation.optional_claims", SUBJECT)
            }
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.anyToken(
                server.issuerUrl(ISSUER_ID),
                mapOf(AUDIENCE to ACCEPTED_AUDIENCE)
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun hello_withValidJWTinCookieShouldGive_200_OK_andHelloCounterIsIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
            header("Cookie", "$idTokenCookieName=${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun hello_withExpiredJWTinCookieShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser", expiry = -120)
            header("Cookie", "$idTokenCookieName=${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun hello_withSoonExpiringJWTinCookieShouldGive_200_OK_andSetTokenExpiresSoonHeader_andHelloCounterIsIncreased() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }

            val response = client.get("/hello") {
                val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser", expiry = 60)
                header("Cookie", "$idTokenCookieName=${jwt.serialize()}")
            }
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals("true", response.headers["x-token-expires-soon"])
        }

    @Test
    fun hello_withoutSoonExpiringJWTinCookieShouldGive_200_OK_andNotSetTokenExpiresSoonHeader() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(ISSUER_ID, "testuser", expiry = Duration.ofMinutes(30).toSeconds()
            )
            header("Cookie", "$idTokenCookieName=${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertNull(response.headers["x-token-expires-soon"])
    }

    @Test
    fun helloPerson_withMissingRequiredClaimShouldGive_401_andHelloCounterIsNotIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello_person") {
            val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun helloPerson_withRequiredClaimShouldGive_200_OK_andHelloCounterIsIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/hello_person") {
            val jwt = server.issueToken(
                issuerId = ISSUER_ID,
                subject = "testuser",
                claims = mapOf("NAVident" to "X112233")
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }


    @Test
    fun openhello_withMissingJWTShouldGive_200_andOpenHelloCounterIsIncreased() = testApplication {
        environment {
            config = doConfig()
            module {
                module()
            }
        }

        val response = client.get("/openhello") {
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun shouldWorkForJWTInHeaderWithhoutCookieConfig() = testApplication {
        environment {
            config = doConfig(hasCookieConfig = false)
            module {
                module()
            }
        }

        val response = client.get("/hello") {
            val jwt = server.issueToken(issuerId = ISSUER_ID, subject = "testuser")
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }


//// hello_group ////

    @Test
    fun helloGroup_withoutRequiredGroup_ShouldGive_401_OK_andHelloGroupCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig(hasCookieConfig = false)
            module {
                module()
            }
        }

        val response = client.get("/hello_group") {
            val jwt = server.issueToken(
                issuerId = ISSUER_ID,
                subject = "testuser",
                claims = mapOf(
                    "NAVident" to "X112233",
                    "groups" to listOf("group1", "group2")
                )
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }


    @Test
    fun helloGroup_withNoGroupClaim_ShouldGive_401_andHelloGroupCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig(hasCookieConfig = false)
            module {
                module()
            }
        }

        val response = client.get("/hello_group") {
            val jwt = server.issueToken(
                issuerId = ISSUER_ID,
                subject = "testuser",
                claims = mapOf(
                    "NAVident" to "X112233",
                )
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }


    @Test
    fun helloGroup_withRequiredGroup_ShouldGive_200_OK_andHelloGroupCounterIsIncreased() = testApplication {
        environment {
            config = doConfig(hasCookieConfig = false)
            module {
                module()
            }
        }

        val response = client.get("/hello_group") {
            val jwt = server.issueToken(
                issuerId = ISSUER_ID,
                subject = "testuser",
                claims = mapOf(
                    "NAVident" to "X112233",
                    "groups" to listOf("group1", "group2", "THEGROUP")
                )
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }


    @Test
    fun helloGroup_withMissingNAVIdentRequiredForAuditLog_ShouldGive_401_andHelloGroupCounterIsNOTIncreased() =
        testApplication {
            application {
                module()
            }
            environment {
                config = doConfig(hasCookieConfig = false)
            }

            val response = client.get("/hello_group") {
                val jwt = server.issueToken(
                    issuerId = ISSUER_ID,
                    subject = "testuser",
                    claims = mapOf(
                        "groups" to listOf("group1", "group2", "THEGROUP")
                    )
                )
                header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
            }
            assertEquals(HttpStatusCode.Unauthorized, response.status)
        }

    private fun doConfig(acceptedIssuer: String = ISSUER_ID, acceptedAudience: String = ACCEPTED_AUDIENCE, hasCookieConfig: Boolean = true): MapApplicationConfig {
        return MapApplicationConfig().apply {
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
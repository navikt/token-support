package no.nav.security.token.support.v3

import com.nimbusds.jwt.JWTClaimNames.AUDIENCE
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.config.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.v3.testapp.module
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.slf4j.LoggerFactory
import kotlin.test.Test
import kotlin.test.assertEquals

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

    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
        }

        application {
            module()
        }

        val response = client.get("/hello")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun hello_withJWTWithUnknownIssuerShouldGive_401_Unauthorized_andHelloCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
        }

        application {
            module()
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
        }

        application {
            module()
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
        }

        application {
            module()
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
        }

        application {
            module()
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
    fun helloPerson_withMissingRequiredClaimShouldGive_401_andHelloCounterIsNotIncreased() = testApplication {
        environment {
            config = doConfig()
        }

        application {
            module()
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
        }

        application {
            module()
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
        }

        application {
            module()
        }

        val response = client.get("/openhello") {
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }


    @Test
    fun helloGroup_withoutRequiredGroup_ShouldGive_401_OK_andHelloGroupCounterIsNOTIncreased() = testApplication {
        environment {
            config = doConfig()
        }

        application {
            module()
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
            config = doConfig()
        }

        application {
            module()
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
            config = doConfig()
        }

        application {
            module()
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
                config = doConfig()
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

    @Test
    fun `requiredClaim with space separated value should match token with multiple space separated values`() =
        testRequiredClaims(
            requiredClaims = arrayOf("scp=custom-scope"),
            tokenClaims = mapOf("scp" to "defaultaccess custom-scope"),
            expectedStatus = HttpStatusCode.OK
        )

    @Test
    fun `requiredClaim with space separated value should fail when value is missing from token`() =
        testRequiredClaims(
            requiredClaims = arrayOf("scp=custom-scope"),
            tokenClaims = mapOf("scp" to "defaultaccess some-other-scope"),
            expectedStatus = HttpStatusCode.Unauthorized
        )

    @Test
    fun `requiredClaim should match regardless of order in space separated values`() =
        testRequiredClaims(
            requiredClaims = arrayOf("scp=scope2 scope1"),
            tokenClaims = mapOf("scp" to "scope1 scope2 scope3"),
            expectedStatus = HttpStatusCode.OK
        )

    @Test
    fun `requiredClaim with array claim should match when value is in the array`() =
        testRequiredClaims(
            requiredClaims = arrayOf("roles=admin"),
            tokenClaims = mapOf("roles" to listOf("user", "admin", "moderator")),
            expectedStatus = HttpStatusCode.OK
        )

    @Test
    fun `requiredClaim with array claim should fail when value is not in the array`() =
        testRequiredClaims(
            requiredClaims = arrayOf("roles=admin"),
            tokenClaims = mapOf("roles" to listOf("user", "moderator")),
            expectedStatus = HttpStatusCode.Unauthorized
        )

    @Test
    fun `requiredClaim with multiple array claims should all be present`() =
        testRequiredClaims(
            requiredClaims = arrayOf("roles=admin", "roles=moderator"),
            tokenClaims = mapOf("roles" to listOf("user", "admin", "moderator")),
            expectedStatus = HttpStatusCode.OK
        )

    private fun testRequiredClaims(
        requiredClaims: Array<String>,
        tokenClaims: Map<String, Any>,
        expectedStatus: HttpStatusCode,
        endpoint: String = "/test"
    ) = testApplication {
        val testConfig = doConfig()
        environment {
            config = testConfig
        }

        application {
            install(Authentication) {
                tokenValidationSupport("testAuth", config = testConfig,
                    requiredClaims = RequiredClaims(issuer = ISSUER_ID, claimMap = requiredClaims)
                )
            }

            routing {
                authenticate("testAuth") {
                    get(endpoint) {
                        call.respondText("Success", ContentType.Text.Plain)
                    }
                }
            }
        }

        val response = client.get(endpoint) {
            val jwt = server.issueToken(
                issuerId = ISSUER_ID,
                subject = "testuser",
                claims = tokenClaims
            )
            header(AUTHORIZATION_HEADER, "Bearer ${jwt.serialize()}")
        }
        assertEquals(expectedStatus, response.status)
    }

    private fun doConfig(acceptedIssuer: String = ISSUER_ID, acceptedAudience: String = ACCEPTED_AUDIENCE): MapApplicationConfig {
        return MapApplicationConfig().apply {
            put("no.nav.security.jwt.expirythreshold", "5")
            put("no.nav.security.jwt.issuers.size", "1")
            put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
            put(
                "no.nav.security.jwt.issuers.0.discoveryurl",
                server.wellKnownUrl(ISSUER_ID).toString()
            )//server.baseUrl() + "/.well-known/openid-configuration")
            put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
        }
    }
}
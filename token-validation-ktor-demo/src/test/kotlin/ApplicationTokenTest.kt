package com.example

import io.ktor.client.request.*
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.config.*
import io.ktor.server.testing.*
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ApplicationTokenTest {
    @Test
    fun hello_withMissingJWTShouldGive_401_Unauthorized()=
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            assertEquals(Unauthorized, client.get("/hello").status)
        }


   @Test
    fun hello_withInvalidJWTShouldGive_401_Unauthorized() =
        testApplication {
            environment {
               config = doConfig()
               module {
                  module()
               }
            }
            val token = server.issueToken(audience = "not-accepted").serialize()
            assertEquals(Unauthorized, client.get("/hello") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }
    @Test
    fun user_withInvalidJWTShouldGive_401_Unauthorized() =
        testApplication {
            environment {
                config = doConfig("some-audience", "some-issuer")
                module {
                    module()
                }
            }
            val token = server.issueToken(claims = mapOf("NAVident" to "Y12345")).serialize()
            assertEquals(Unauthorized, client.get("/user") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    @Test
    fun users_withInvalidJWTShouldGive_401_Unauthorized() =
        testApplication {
            environment {
                config = doConfig("some-audience", "some-issuer")
                module {
                    module()
                }
            }
            val token = server.issueToken(claims = mapOf("NAVident" to "Y12345")).serialize()
            assertEquals(Unauthorized, client.get("/users") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    @Test
    fun scope_withInvalidJWTShouldGive_401_Unauthorized() =
        testApplication {
            environment {
                config = doConfig("some-audience", "some-issuer")
                module {
                    module()
                }
            }
            val token = server.issueToken(claims = mapOf("scope" to "nav:domain:invalid")).serialize()
            assertEquals(Unauthorized, client.get("/scope") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    @Test
    fun hello_withValidJWTinHeaderShouldGive_200_OK() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            val token = server.issueToken().serialize()
            assertEquals(OK, client.get("/hello") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    @Test
    fun openhello_withMissingJWTShouldGive_200() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            assertEquals(OK, client.get("/openhello").status)
        }

    @Test
    fun user_withValidJWTinHeaderShouldGive_200_OK() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            val token = server.issueToken(claims = mapOf("NAVident" to "X12345")).serialize()
            assertEquals(OK, client.get("/user") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }
    @Test
    fun users_withValidJWTinHeaderShouldGive_200_OK() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            val token = server.issueToken(claims = mapOf("NAVident" to "X12345")).serialize()
            assertEquals(OK, client.get("/users") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    @Test
    fun scope_withValidJWTinHeaderShouldGive_200_OK() =
        testApplication {
            environment {
                config = doConfig()
                module {
                    module()
                }
            }
            var token = server.issueToken(claims = mapOf("scope" to "nav:domain:read nav:domain:write")).serialize()
            assertEquals(OK, client.get("/scope") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)

             token = server.issueToken(claims = mapOf("scope" to "nav:domain:write")).serialize()
            assertEquals(OK, client.get("/scope") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)

            token = server.issueToken(claims = mapOf("scope" to "nav:domain:read")).serialize()
            assertEquals(OK, client.get("/scope") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)

            token = server.issueToken(claims = mapOf("scope" to "nav:domain:read nav:domain:other")).serialize()
            assertEquals(OK, client.get("/scope") {
                header(AUTHORIZATION_HEADER, "Bearer $token")
            }.status)
        }

    companion object {

        private fun doConfig(
            acceptedIssuer: String = "default",
            acceptedAudience: String = "default"): MapApplicationConfig {
            return MapApplicationConfig().apply {
                put("no.nav.security.jwt.issuers.size", "1")
                put("no.nav.security.jwt.issuers.0.issuer_name", acceptedIssuer)
                put("no.nav.security.jwt.issuers.0.discoveryurl", "${server.wellKnownUrl(acceptedIssuer)}")
                put("no.nav.security.jwt.issuers.0.accepted_audience", acceptedAudience)
            }
        }
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
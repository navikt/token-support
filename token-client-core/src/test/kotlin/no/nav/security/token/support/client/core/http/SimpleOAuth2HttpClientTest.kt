package no.nav.security.token.support.client.core.http

import io.kotest.assertions.assertSoftly
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets.UTF_8
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.TestUtils.jsonResponse
import no.nav.security.token.support.client.core.TestUtils.withMockServer
import tools.jackson.core.JacksonException

internal class SimpleOAuth2HttpClientTest : BehaviorSpec({
    Given("et tokenendepunkt som svarer med suksess") {
        listOf(200, 201, 299).forEach { status ->
            When("HTTP $status mottas med token i JSON-format og ekstra felter") {
                Then("skal deserialisere tokenet og ignorere ukjente felter") {
                    withMockServer { server ->
                        server.enqueue(jsonResponse(
                            """{"access_token":"access","expires_at":1234,"expires_in":60,"extra":"ignored"}"""
                        ).setResponseCode(status))
                        val response = SimpleOAuth2HttpClient().post(
                            OAuth2HttpRequest.builder(URI.create(server.url("/token").toString())).build()
                        )
                        assertSoftly(response) {
                            access_token shouldBe "access"
                            expires_at shouldBe 1234
                            expires_in shouldBe 60
                        }
                    }
                }
            }
        }
        When("ugyldig formatert JSON mottas") {
            Then("skal synliggjøre deserialiseringsfeilen") {
                withMockServer { server ->
                    server.enqueue(jsonResponse("not-json"))
                    shouldThrow<JacksonException> {
                        SimpleOAuth2HttpClient().post(
                            OAuth2HttpRequest.builder(URI.create(server.url("/token").toString())).build()
                        )
                    }
                }
            }
        }
        When("et tomt HTTP 204-svar mottas") {
            Then("skal avvise den manglende tokenresponsen") {
                withMockServer { server ->
                    server.enqueue(jsonResponse("").setResponseCode(204))
                    shouldThrow<JacksonException> {
                        SimpleOAuth2HttpClient().post(
                            OAuth2HttpRequest.builder(URI.create(server.url("/token").toString())).build()
                        )
                    }
                }
            }
        }
    }

    Given("et tokenendepunkt som returnerer en feil") {
        listOf(400, 401, 500).forEach { status ->
            When("HTTP $status mottas") {
                Then("skal rapportere statusen og responsinnholdet") {
                    withMockServer { server ->
                        val body = """{"error":"invalid_client"}"""
                        server.enqueue(jsonResponse(body).setResponseCode(status))
                        val exception = shouldThrow<OAuth2ClientException> {
                            SimpleOAuth2HttpClient().post(
                                OAuth2HttpRequest.builder(URI.create(server.url("/token").toString())).build()
                            )
                        }
                        assertSoftly(exception) {
                            message shouldContain status.toString()
                            message shouldContain body
                        }
                    }
                }
            }
        }
    }

    Given("skjemaparametere som inneholder reserverte tegn og tegn utenfor ASCII") {
        When("forespørselen sendes med POST") {
            Then("skal kode hver verdi uten å opprette ekstra parametere og bevare gjentatte headere") {
                withMockServer { server ->
                    server.enqueue(jsonResponse("""{"access_token":"access"}"""))
                    val parameters = mapOf(
                        "scope" to "read + write&admin=1",
                        "assertion" to "a+b/c?=\u00e6"
                    )
                    val request = OAuth2HttpRequest.builder(URI.create(server.url("/token").toString()))
                        .formParameters(parameters)
                        .oAuth2HttpHeaders(OAuth2HttpHeaders.builder()
                            .header("X-Test", "first")
                            .header("X-Test", "second")
                            .build())
                        .build()
                    SimpleOAuth2HttpClient().post(request)
                    val recordedRequest = server.takeRequest()
                    val decoded = recordedRequest.body.readUtf8().split("&").associate { parameter ->
                        val (key, value) = parameter.split("=", limit = 2)
                        key to URLDecoder.decode(value, UTF_8)
                    }
                    assertSoftly(recordedRequest) {
                        method shouldBe "POST"
                        headers.values("X-Test") shouldBe listOf("first", "second")
                        decoded shouldBe parameters
                    }
                }
            }
        }
    }

    Given("et utilgjengelig tokenendepunkt") {
        When("en tokenforespørsel sendes med POST") {
            Then("skal synliggjøre tilkoblingsfeilen") {
                lateinit var endpoint: URI
                withMockServer { server ->
                    endpoint = URI.create(server.url("/token").toString())
                }
                shouldThrow<IOException> {
                    SimpleOAuth2HttpClient().post(OAuth2HttpRequest.builder(endpoint).build())
                }
            }
        }
    }
})

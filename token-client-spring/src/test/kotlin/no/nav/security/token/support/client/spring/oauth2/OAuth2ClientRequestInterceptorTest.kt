package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import java.io.IOException
import java.net.URI
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.mock.http.client.MockClientHttpRequest
import org.springframework.mock.http.client.MockClientHttpResponse

internal class OAuth2ClientRequestInterceptorTest : BehaviorSpec({
    val registration = TestUtils.clientProperties()
    val properties = ClientConfigurationProperties(mapOf("resource" to registration))
    val body = "request-body".toByteArray()
    lateinit var service: OAuth2AccessTokenService
    lateinit var execution: ClientHttpRequestExecution
    lateinit var request: MockClientHttpRequest
    lateinit var response: MockClientHttpResponse
    lateinit var interceptor: OAuth2ClientRequestInterceptor

    beforeEach {
        service = mock()
        execution = mock()
        request = MockClientHttpRequest(HttpMethod.POST, URI.create("https://resource.example/api"))
        response = MockClientHttpResponse("response-body".toByteArray(), HttpStatus.OK)
        interceptor = OAuth2ClientRequestInterceptor(properties, service)
        whenever(execution.execute(request, body)).thenReturn(response)
    }

    Given("en forespørsel som matcher en klientregistrering") {
        When("en Authorization-header allerede finnes") {
            Then("skal erstatte den og bevare forespørselsinnholdet og responsen") {
                request.headers.setBearerAuth("original")
                request.headers.add("X-Custom", "value")
                whenever(service.getAccessToken(registration)).thenReturn(OAuth2AccessTokenResponse("replacement"))
                val actualResponse = interceptor.intercept(request, body, execution)
                assertSoftly(request) {
                    headers["Authorization"] shouldBe listOf("Bearer replacement")
                    headers["X-Custom"] shouldBe listOf("value")
                    actualResponse shouldBe response
                }
                verify(service).getAccessToken(registration)
                verify(execution).execute(request, body)
            }
        }
        When("det ikke finnes en Authorization-header") {
            Then("skal likevel hente og sette tilgangstokenet") {
                whenever(service.getAccessToken(registration)).thenReturn(OAuth2AccessTokenResponse("access"))
                interceptor.intercept(request, body, execution) shouldBe response
                request.headers["Authorization"] shouldBe listOf("Bearer access")
                verify(service).getAccessToken(registration)
                verify(execution).execute(request, body)
            }
        }
        When("responsen ikke har et tilgangstoken") {
            Then("skal bevare den opprinnelige Authorization-headeren og utføre forespørselen") {
                request.headers.setBearerAuth("original")
                whenever(service.getAccessToken(registration)).thenReturn(OAuth2AccessTokenResponse())
                interceptor.intercept(request, body, execution) shouldBe response
                request.headers["Authorization"] shouldBe listOf("Bearer original")
                verify(execution).execute(request, body)
            }
        }
        When("henting av token feiler") {
            Then("skal videreformidle feilen uten å utføre forespørselen") {
                val error = OAuth2ClientException("Token endpoint failed")
                whenever(service.getAccessToken(registration)).thenAnswer { throw error }
                shouldThrow<OAuth2ClientException> {
                    interceptor.intercept(request, body, execution)
                } shouldBe error
                verifyNoInteractions(execution)
            }
        }
        When("utføring av forespørselen feiler etter henting av token") {
            Then("skal videreformidle utføringsfeilen uten å prøve på nytt") {
                whenever(service.getAccessToken(registration)).thenReturn(OAuth2AccessTokenResponse("access"))
                val error = IOException("Request execution failed")
                whenever(execution.execute(request, body)).thenAnswer { throw error }
                shouldThrow<IOException> {
                    interceptor.intercept(request, body, execution)
                } shouldBe error
                request.headers["Authorization"] shouldBe listOf("Bearer access")
                verify(service).getAccessToken(registration)
                verify(execution).execute(request, body)
            }
        }
    }

    Given("en forespørsel uten en matchende registrering") {
        When("forespørselen fanges opp") {
            Then("skal bevare headeren og utføre forespørselen uten å hente et token") {
                interceptor = OAuth2ClientRequestInterceptor(ClientConfigurationProperties(emptyMap()), service)
                request.headers.setBearerAuth("original")
                interceptor.intercept(request, body, execution) shouldBe response
                request.headers["Authorization"] shouldBe listOf("Bearer original")
                verifyNoInteractions(service)
                verify(execution).execute(request, body)
            }
        }
    }

    Given("en egendefinert matcher") {
        When("den velger en registrering") {
            Then("skal bruke resultatet fremfor å matche vertsnavnet") {
                val matcher = PathPrefixClientConfigurationPropertiesMatcher(listOf("/api" to "custom"))
                interceptor = OAuth2ClientRequestInterceptor(
                    ClientConfigurationProperties(mapOf("custom" to registration)), service, matcher
                )
                whenever(service.getAccessToken(registration)).thenReturn(OAuth2AccessTokenResponse("custom-access"))
                interceptor.intercept(request, body, execution) shouldBe response
                request.headers["Authorization"] shouldBe listOf("Bearer custom-access")
                verify(service).getAccessToken(registration)
                verify(execution).execute(request, body)
            }
        }
    }
})

package no.nav.security.token.support.ktor.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.request.forms.submitForm
import io.ktor.http.Parameters
import kotlinx.coroutines.runBlocking
import no.nav.security.token.support.client.core.OAuth2ParameterNames
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

class DefaultOAuth2HttpClient : OAuth2HttpClient {

    private val objectMapper: ObjectMapper = ObjectMapper()
        .registerKotlinModule()
        .configure(SerializationFeature.INDENT_OUTPUT, true)

    private val defaultHttpClient =
        HttpClient(CIO) {
            install(JsonFeature) {
                serializer = JacksonSerializer { objectMapper }
            }
        }

    override fun post(oAuth2HttpRequest: OAuth2HttpRequest): OAuth2AccessTokenResponse {
        return runBlocking {
            defaultHttpClient.submitForm<OAuth2AccessTokenResponse>(
                url = oAuth2HttpRequest.tokenEndpointUrl.toString(),
                formParameters = Parameters.build {
                    formParams(oAuth2HttpRequest).forEach {
                        append(it.key, it.value)
                    }
                    append(
                        OAuth2ParameterNames.ASSERTION,
                        oAuth2HttpRequest.formParameters[OAuth2ParameterNames.ASSERTION]
                            ?: throw RuntimeException("Client Assertion could not be retrieved")
                    )
                }
            )
        }
    }

    private fun formParams(oAuth2HttpRequest: OAuth2HttpRequest) = oAuth2HttpRequest.formParameters
        .filterNot { param ->
            param.key == OAuth2ParameterNames.REQUESTED_TOKEN_USE
        }
}

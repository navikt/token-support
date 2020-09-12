package no.nav.security.token.support.ktor.http

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
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

    private val defaultHttpClient = HttpClient(CIO) {
        install(JsonFeature) {
            serializer = JacksonSerializer {
                configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                setSerializationInclusion(JsonInclude.Include.NON_NULL)
            }
        }
    }

    // Override default POST with other form parameters specified for Idp request
    override fun post(oAuth2HttpRequest: OAuth2HttpRequest): OAuth2AccessTokenResponse {
        return runBlocking {
            defaultHttpClient.submitForm<OAuth2AccessTokenResponse>(
                url = oAuth2HttpRequest.tokenEndpointUrl.toString(),
                formParameters = Parameters.build {
                    filterFormParams(oAuth2HttpRequest).forEach {
                        append(it.key, it.value)
                    }
                }
            )
        }
    }

    private fun filterFormParams(oAuth2HttpRequest: OAuth2HttpRequest) = oAuth2HttpRequest.formParameters
        .filterNot {
            it.key == OAuth2ParameterNames.REQUESTED_TOKEN_USE
        }.filterNot {
            it.key == OAuth2ParameterNames.CLIENT_ID
        }.filterNot {
            it.key == OAuth2ParameterNames.CLIENT_ASSERTION_TYPE
        }
}

package no.nav.security.token.support.client.core.http

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.net.URLEncoder
import java.net.http.HttpClient.newHttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandlers
import java.nio.charset.StandardCharsets.UTF_8
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

class SimpleOAuth2HttpClient : OAuth2HttpClient {

    override fun post(request: OAuth2HttpRequest) =
        HttpRequest.newBuilder().apply {
            configureRequest(request)
        }.build()
            .sendRequest()
            .processResponse()

    private fun HttpRequest.Builder.configureRequest(request: OAuth2HttpRequest): HttpRequest.Builder {
        request.oAuth2HttpHeaders.headers.forEach { (key, values) -> values.forEach { header(key, it) } }
        uri(request.tokenEndpointUrl)
        POST(BodyPublishers.ofString(request.formParameters.toUrlEncodedString()))
        return this
    }

    private fun HttpRequest.sendRequest() = newHttpClient().send(this, BodyHandlers.ofString())
    private fun HttpResponse<String>.processResponse() =
        if (this.statusCode() in 200..299) {
            MAPPER.readValue<OAuth2AccessTokenResponse>(body())
        } else {
            throw OAuth2ClientException("Error response from token endpoint: ${this.statusCode()} ${this.body()}")
        }
    private fun Map<String, String>.toUrlEncodedString() = entries.joinToString("&") { (key, value) -> "$key=${URLEncoder.encode(value, UTF_8)}" }
    companion object {
        private val MAPPER = jacksonObjectMapper().configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
    }
}
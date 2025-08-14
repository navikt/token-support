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

    override fun post(req: OAuth2HttpRequest) =
        HttpRequest.newBuilder().configureRequest(req)
            .build()
            .sendRequest()
            .processResponse()

    private fun HttpRequest.Builder.configureRequest(req: OAuth2HttpRequest): HttpRequest.Builder {
        req.oAuth2HttpHeaders.headers.forEach { (key, value) ->  { header(key, value)  }}
        uri(req.tokenEndpointUrl)
        POST(BodyPublishers.ofString(req.formParameters.toUrlEncodedString()))
        return this
    }

    private fun HttpRequest.sendRequest() = newHttpClient().send(this, BodyHandlers.ofString())
    private fun HttpResponse<String>.processResponse() =
        if (statusCode() in 200..299) {
            MAPPER.readValue<OAuth2AccessTokenResponse>(body())
        } else {
            throw OAuth2ClientException("Error response from token endpoint: ${statusCode()} ${body()}")
        }
    private fun Map<String, String>.toUrlEncodedString() = entries.joinToString("&") { (key, value) -> "$key=${URLEncoder.encode(value, UTF_8)}" }
    companion object {
        private val MAPPER = jacksonObjectMapper().configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
    }
}
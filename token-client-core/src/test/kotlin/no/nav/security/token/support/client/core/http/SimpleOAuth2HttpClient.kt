package no.nav.security.token.support.client.core.http

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.net.URLEncoder
import java.net.URLEncoder.*
import java.net.http.HttpClient.*
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandlers.*
import java.nio.charset.StandardCharsets.*
import org.slf4j.LoggerFactory
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

class SimpleOAuth2HttpClient : OAuth2HttpClient {

    override fun post(oAuth2HttpRequest : OAuth2HttpRequest) =
        try {
            val httpRequest = HttpRequest.newBuilder().apply {
                with(oAuth2HttpRequest) {
                    oAuth2HttpHeaders?.headers?.forEach { (key, values) ->
                        values.forEach { value -> header(key, value) }
                    }
                    uri(tokenEndpointUrl)
                    POST(BodyPublishers.ofString(formParameters.entries.joinToString("&") { (key, value) -> "$key=${encode(value, UTF_8)}" }))
                } }.build()
            MAPPER.readValue<OAuth2AccessTokenResponse>(bodyAsString(newHttpClient().send(httpRequest, ofString())))
        }
        catch (e : Exception) {
            if (e !is RuntimeException) throw RuntimeException(e)
            else throw e
        }

    private fun bodyAsString(response : HttpResponse<String>?) = response?.let {
        log.debug("Received response in client, body={}", response.body())
            if (it.statusCode() == 200) {
                it.body()
            }
            else {
                throw RuntimeException("Received status code=${response.statusCode()} and response body=${response.body()} from authorization server.")
            }
            } ?:  throw RuntimeException("Response cannot be null.")

    companion object {
        private val MAPPER = jacksonObjectMapper().configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
        private val log = LoggerFactory.getLogger(SimpleOAuth2HttpClient::class.java)
    }
}
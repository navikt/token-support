package no.nav.security.token.support.client.core.http

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import java.io.IOException
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandlers
import java.nio.charset.StandardCharsets
import java.util.Optional
import java.util.function.Consumer
import java.util.stream.Collectors
import kotlin.collections.Map.Entry
import org.slf4j.LoggerFactory
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

class SimpleOAuth2HttpClient : OAuth2HttpClient {

    private val objectMapper : ObjectMapper

    init {
        objectMapper = ObjectMapper().registerModule(KotlinModule.Builder().build())
            .configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
    }

    override fun post(oAuth2HttpRequest : OAuth2HttpRequest) : OAuth2AccessTokenResponse? {
        return try {
            val requestBuilder = HttpRequest.newBuilder()
            oAuth2HttpRequest.oAuth2HttpHeaders!!
                .headers().forEach { (key : String?, value : List<String?>) ->
                    value.forEach(
                        Consumer { v : String? -> requestBuilder.header(key, v) })
                }
            val body = oAuth2HttpRequest.formParameters.entries.stream()
                .map { (key, value) : Entry<String, String?> -> key + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8) }
                .collect(Collectors.joining("&"))
            val httpRequest = requestBuilder
                .uri(oAuth2HttpRequest.tokenEndpointUrl)
                .POST(BodyPublishers.ofString(body))
                .build()
            val response = HttpClient.newHttpClient().send(httpRequest, BodyHandlers.ofString())
            objectMapper.readValue(bodyAsString(response), OAuth2AccessTokenResponse::class.java)
        }
        catch (e : IOException) {
            throw RuntimeException(e)
        }
        catch (e : InterruptedException) {
            throw RuntimeException(e)
        }
    }

    private fun bodyAsString(response : HttpResponse<String>?) : String {
        if (response != null) {
            log.debug("received response in client, body={}", response.body())
            return Optional.of(response)
                .filter { r : HttpResponse<String> -> r.statusCode() == 200 }
                .map { obj : HttpResponse<String> -> obj.body() }
                .orElseThrow {
                    RuntimeException("received status code=" + response.statusCode()
                        + " and response body=" + response.body() + " from authorization server.")
                }
        }
        throw RuntimeException("response cannot be null.")
    }

    companion object {

        private val log = LoggerFactory.getLogger(SimpleOAuth2HttpClient::class.java)
    }
}
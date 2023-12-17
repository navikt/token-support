package no.nav.security.token.support.demo.spring.mockwebserver

import jakarta.annotation.PreDestroy
import java.io.IOException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Arrays
import java.util.Optional
import java.util.function.Function
import java.util.stream.Collectors
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType

@Configuration
class MockWebServerConfiguration(@param:Value("\${mockwebserver.port}") private val port : Int) {


    private val server = MockWebServer()

    init {
        setup()
    }

    private fun setup() {
        server.start(port)
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request : RecordedRequest) : MockResponse {
                log.info("received request on url={} with headers={}", request.requestUrl, request.headers)
                return mockResponse(request)
            }
        }
    }

    private fun mockResponse(request : RecordedRequest) : MockResponse {
        val body = request.body.readUtf8()
        if (isTokenRequest(request)) {
            val formParams = formParameters(body)
            log.info("form parameters decoded: {}", formParams)
            return tokenResponse(formParams)
        }
        else {
            return MockResponse()
                .setResponseCode(200)
                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .setBody(DEFAULT_JSON_RESPONSE)
        }
    }

    private fun tokenResponse(formParams : Map<String, String>) : MockResponse {
        val response = TOKEN_RESPONSE_TEMPLATE
            .replace("\$scope", formParams["scope"]!!)
            .replace("\$expires_at", "" + Instant.now().plusSeconds(3600).epochSecond)
            .replace("\$ext_expires_in", "30")
            .replace("\$expires_in", "30")
            .replace("\$access_token", "somerandomaccesstoken")

        log.info("returning tokenResponse={}", response)
        return MockResponse()
            .setResponseCode(200)
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .setBody(response)
    }

    @PreDestroy
    fun shutdown() {
        server.shutdown()
    }

    private fun isTokenRequest(request : RecordedRequest) : Boolean {
        return request.requestUrl.toString().endsWith(TOKEN_ENDPOINT_URI) &&
            Optional.ofNullable(request.getHeader("Content-Type"))
                .filter { h : String -> h.contains("application/x-www-form-urlencoded") }
                .isPresent
    }

    private fun formParameters(formUrlEncodedString : String) : Map<String, String> {
        return Arrays.stream(formUrlEncodedString.split("&".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray())
            .map { value : String -> this.decode(value) }
            .map { s : String -> s.split("=".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray() }
            .collect(Collectors.toMap(
                Function { array : Array<String> -> array[0] }, Function { array : Array<String> -> array[1] }))
    }

    private fun decode(value : String) : String {
        return URLDecoder.decode(value, StandardCharsets.UTF_8)
    }

    companion object {

        private val TOKEN_RESPONSE_TEMPLATE = """
        {
          "token_type": "Bearer",
          "scope": "${'$'}scope",
          "expires_at": ${'$'}expires_at",
          "ext_expires_in": ${'$'}ext_expires_in",
          "expires_in": ${'$'}expires_in",
          "access_token": "${'$'}access_token"
        }
        
        """.trimIndent()

        private val DEFAULT_JSON_RESPONSE = """
        {
          "ping": "pong"
        }
        
        """.trimIndent()

        private const val TOKEN_ENDPOINT_URI = "/oauth2/v2.0/token"
        private val log : Logger = LoggerFactory.getLogger(MockWebServerConfiguration::class.java)
    }
}
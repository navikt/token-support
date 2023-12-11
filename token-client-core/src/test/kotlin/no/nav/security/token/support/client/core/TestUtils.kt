package no.nav.security.token.support.client.core

import com.nimbusds.common.contenttype.ContentType.*
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*
import java.io.UnsupportedEncodingException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime.*
import java.time.ZoneId.*
import java.util.Base64
import java.util.Date
import java.util.Optional
import java.util.UUID
import java.util.function.Consumer
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.*
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder

object TestUtils {
    @JvmStatic
    fun clientProperties(tokenEndpointUrl : String, oAuth2GrantType : GrantType) =
        builder(oAuth2GrantType, builder("client1", CLIENT_SECRET_BASIC)
            .clientSecret("clientSecret1")
            .build())
            .scope(listOf("scope1", "scope2"))
            .tokenEndpointUrl(URI.create(tokenEndpointUrl))
            .build()

    @JvmStatic
    fun withMockServer(test: (MockWebServer) -> Unit) {
        MockWebServer().run {
            start()
            test(this)
            shutdown()
        }
    }

    @JvmStatic
    fun jsonResponse(json : String) = MockResponse().apply {
        setHeader("Content-Type", "$APPLICATION_JSON")
        setBody(json)
    }

    @JvmStatic
    fun assertPostMethodAndJsonHeaders(recordedRequest : RecordedRequest) {
        assertThat(recordedRequest.method).isEqualTo("POST")
        assertThat(recordedRequest.getHeader("Accept")).isEqualTo("$APPLICATION_JSON")
        assertThat(recordedRequest.getHeader("Content-Type")).isEqualTo("$APPLICATION_URLENCODED")
    }

    @JvmStatic
    fun decodeBasicAuth(recordedRequest : RecordedRequest) : String {
        return Optional.ofNullable(recordedRequest.headers["Authorization"])
            .map { s : String -> s.split("Basic ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray() }
            .filter { pair : Array<String> -> pair.size == 2 }
            .map { pair : Array<String> -> Base64.getDecoder().decode(pair[1]) }
            .map { bytes : ByteArray? -> String(bytes!!, StandardCharsets.UTF_8) }
            .orElse("")
    }

    @JvmStatic
    fun jwt(sub : String?) = PlainJWT(Builder()
        .subject(sub)
        .audience("thisapi")
        .issuer("someIssuer")
        .expirationTime(Date.from(now().atZone(systemDefault()).plusSeconds(60).toInstant()))
        .claim("jti", UUID.randomUUID().toString())
        .build())

    @JvmStatic
    fun encodeValue(value : String?) : String? {
        var encodedUrl : String? = null
        try {
            encodedUrl = URLEncoder.encode(value, StandardCharsets.UTF_8.toString())
        }
        catch (e : UnsupportedEncodingException) {
            e.printStackTrace()
        }
        return encodedUrl
    }
}
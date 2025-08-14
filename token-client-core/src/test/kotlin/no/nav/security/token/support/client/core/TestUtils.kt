package no.nav.security.token.support.client.core

import com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON
import com.nimbusds.common.contenttype.ContentType.APPLICATION_URLENCODED
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import java.io.UnsupportedEncodingException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime.now
import java.time.ZoneId.systemDefault
import java.util.*
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import org.assertj.core.api.Assertions.assertThat

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
        MockWebServer().apply {
            start()
            test(this)
            close()
        }
    }

    @JvmStatic
    fun jsonResponse(json : String) = MockResponse(body = json).apply {
        headers.newBuilder().add("Content-Type", "application/json").build()
    }

    @JvmStatic
    fun assertPostMethodAndJsonHeaders(recordedRequest : RecordedRequest) {
        assertThat(recordedRequest.method).isEqualTo("POST")
        assertThat(recordedRequest.headers.get("Accept")).isEqualTo("$APPLICATION_JSON")
        assertThat(recordedRequest.headers.get("Content-Type")).isEqualTo("$APPLICATION_URLENCODED")
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
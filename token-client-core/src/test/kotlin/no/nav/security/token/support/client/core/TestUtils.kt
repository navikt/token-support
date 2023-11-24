package no.nav.security.token.support.client.core

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Base64
import java.util.Date
import java.util.Optional
import java.util.UUID
import java.util.function.Consumer
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions
import no.nav.security.token.support.client.core.ClientAuthenticationProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.Companion.builder
import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties

object TestUtils {

    const val CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8"
    const val CONTENT_TYPE_JSON = "application/json;charset=UTF-8"
    @JvmStatic
    fun clientProperties(tokenEndpointUrl : String?, oAuth2GrantType : OAuth2GrantType?) : ClientProperties {
        return builder(oAuth2GrantType!!, builder("client1", ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientSecret("clientSecret1")
            .build())
            .scope(listOf("scope1", "scope2"))
            .tokenEndpointUrl(URI.create(tokenEndpointUrl))
            .build()
    }

    fun tokenExchangeClientProperties(
        tokenEndpointUrl : String?,
        oAuth2GrantType : OAuth2GrantType?,
        clientPrivateKey : String?
                                     ) : ClientProperties {
        return builder(oAuth2GrantType!!, builder("client1", ClientAuthenticationMethod.PRIVATE_KEY_JWT)
            .clientJwk(clientPrivateKey!!)
            .build())
            .tokenEndpointUrl(URI.create(tokenEndpointUrl))
            .tokenExchange(TokenExchangeProperties("audience"))
            .build()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun withMockServer(test : Consumer<MockWebServer?>) {
        val server = MockWebServer()
        server.start()
        test.accept(server)
        server.shutdown()
    }

    @JvmStatic
    fun jsonResponse(json : String?) : MockResponse {
        return MockResponse()
            .setHeader("Content-Type", "application/json;charset=UTF-8")
            .setBody(json!!)
    }

    @JvmStatic
    fun assertPostMethodAndJsonHeaders(recordedRequest : RecordedRequest) {
        Assertions.assertThat(recordedRequest.method).isEqualTo("POST")
        Assertions.assertThat(recordedRequest.getHeader("Accept")).isEqualTo(CONTENT_TYPE_JSON)
        Assertions.assertThat(recordedRequest.getHeader("Content-Type")).isEqualTo(CONTENT_TYPE_FORM_URL_ENCODED)
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
    fun jwt(sub : String?) : JWT {
        val expiry = LocalDateTime.now().atZone(ZoneId.systemDefault()).plusSeconds(60).toInstant()
        return PlainJWT(Builder()
            .subject(sub)
            .audience("thisapi")
            .issuer("someIssuer")
            .expirationTime(Date.from(expiry))
            .claim("jti", UUID.randomUUID().toString())
            .build())
    }

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
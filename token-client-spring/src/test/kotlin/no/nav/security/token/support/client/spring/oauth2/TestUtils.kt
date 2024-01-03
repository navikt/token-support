package no.nav.security.token.support.client.spring.oauth2


import okhttp3.mockwebserver.MockResponse
import org.springframework.http.HttpHeaders.CONTENT_TYPE
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE

internal object TestUtils {

    fun jsonResponse(json: String)=
         MockResponse().apply {
            setHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
            setBody(json)
    }
}
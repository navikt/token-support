package no.nav.security.token.support.client.spring.oauth2


import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import no.nav.security.token.support.client.core.ClientAuthenticationPropertiesBuilder
import no.nav.security.token.support.client.core.ClientProperties
import okhttp3.mockwebserver.MockResponse
import org.springframework.http.HttpHeaders.CONTENT_TYPE
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE

internal object TestUtils {

    fun jsonResponse(json: String)=
         MockResponse().apply {
            setHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
            setBody(json)
    }

    fun clientProperties(clientId: String = "client") =
        ClientProperties.builder(
            CLIENT_CREDENTIALS,
            ClientAuthenticationPropertiesBuilder(clientId, CLIENT_SECRET_BASIC)
                .clientSecret("secret")
                .build()
        ).tokenEndpointUrl("https://tokens.example/token").build()

}
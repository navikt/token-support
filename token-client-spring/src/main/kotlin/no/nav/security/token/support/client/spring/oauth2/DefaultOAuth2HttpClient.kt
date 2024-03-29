package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import org.springframework.http.HttpHeaders
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient
import org.springframework.web.client.body

open class DefaultOAuth2HttpClient(val restClient: RestClient) : OAuth2HttpClient {


    override fun post(req: OAuth2HttpRequest) =
        restClient.post()
            .uri(req.tokenEndpointUrl)
            .headers { it.addAll(headers(req)) }
            .body(LinkedMultiValueMap<String, String>().apply {
                setAll(req.formParameters)
            }).retrieve()
            .onStatus({ it.isError }) { _, response ->
                throw OAuth2ClientException("Received ${response.statusCode} from ${req.tokenEndpointUrl}")
            }
            .body<OAuth2AccessTokenResponse>() ?: throw OAuth2ClientException("No body in response from ${req.tokenEndpointUrl}")

     private fun headers(req: OAuth2HttpRequest): HttpHeaders  = HttpHeaders().apply { putAll(req.oAuth2HttpHeaders.headers) }

    override fun toString() = "${javaClass.simpleName}  [restClient=$restClient]"
}
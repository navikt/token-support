package no.nav.security.token.support.client.spring.oauth2

import org.springframework.http.HttpHeaders
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

open class DefaultOAuth2HttpClient(val restClient: RestClient) : OAuth2HttpClient {


    override fun post(oAuth2HttpRequest: OAuth2HttpRequest) =
        restClient.post()
            .uri(oAuth2HttpRequest.tokenEndpointUrl!!)
            .headers { it.addAll(headers(oAuth2HttpRequest)) }
            .body(LinkedMultiValueMap<String, String>().apply {
                setAll(oAuth2HttpRequest.formParameters)
            }).retrieve()
            .onStatus({ it.isError }) { _, response ->
                throw OAuth2ClientException("Received $response.statusCode from $oAuth2HttpRequest.tokenEndpointUrl")
            }
            .body(OAuth2AccessTokenResponse::class.java)

     private fun headers(req: OAuth2HttpRequest): HttpHeaders  = HttpHeaders().apply { req.oAuth2HttpHeaders?.let { putAll(it.headers) } }

    override fun toString() = "$javaClass.simpleName  [restClient=$restClient]"
}
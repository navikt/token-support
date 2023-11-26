package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod.POST
import org.springframework.http.RequestEntity
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.HttpStatusCodeException
import org.springframework.web.client.RestOperations
 open class DefaultOAuth2HttpClient(val restOperations: RestOperations) : OAuth2HttpClient {
    constructor(builder: RestTemplateBuilder) :this(builder.build())


    override fun post(oAuth2HttpRequest: OAuth2HttpRequest) =
         try {
             restOperations.exchange(convert(oAuth2HttpRequest), OAuth2AccessTokenResponse::class.java).body
        } catch (e: HttpStatusCodeException) {
            throw OAuth2ClientException("Received $e.statusCode from tokenendpoint $oAuth2HttpRequest.tokenEndpointUrl with responsebody $e.responseBodyAsString", e)
        }

    private fun convert(req: OAuth2HttpRequest) =
         with(req) {
                 RequestEntity(
                     LinkedMultiValueMap<String, String>().apply { setAll(formParameters) },
                     headers(this),
                     POST,
                     tokenEndpointUrl!!)
         }

    private fun headers(req: OAuth2HttpRequest): HttpHeaders  = HttpHeaders().apply { req.oAuth2HttpHeaders?.let { putAll(it.headers()) } }

    override fun toString() = "$javaClass.simpleName  [restTemplate=$restOperations]"
}
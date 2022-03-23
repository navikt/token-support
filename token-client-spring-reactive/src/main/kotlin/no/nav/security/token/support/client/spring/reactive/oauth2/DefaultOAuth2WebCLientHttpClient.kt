package no.nav.security.token.support.client.spring.reactive.oauth2

import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters.fromMultipartData
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono


class DefaultOAuth2WebCLientHttpClient(private var client: WebClient) :OAuth2HttpClient {
    private val log = LoggerFactory.getLogger(DefaultOAuth2WebCLientHttpClient::class.java)
    override fun post(req: OAuth2HttpRequest) =
         with(req) {
             client.post()
                 .uri(tokenEndpointUrl)
                 .accept(APPLICATION_JSON)
                 .headers { HttpHeaders()
                     .apply {
                         putAll(oAuth2HttpHeaders.headers())
                     }
                 }
                 .body(fromMultipartData(LinkedMultiValueMap<String, String>()
                     .apply {
                         setAll(formParameters) }))
            .retrieve()
            .bodyToMono<OAuth2AccessTokenResponse>()
                 .doOnSuccess {
                     log.trace(" POST $tokenEndpointUrl OK")
                 }
                 .doOnError {
                t: Throwable -> log.warn(" POST $tokenEndpointUrl feilet", t)
            }
            .blockOptional()
                 .orElseThrow()  // or whatever
        }
}
package no.nav.security.token.support.client.spring.reactive.oauth2

import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono


class DefaultOAuth2WebClientHttpClient(private var client: WebClient) :OAuth2HttpClient {
    private val log = LoggerFactory.getLogger(DefaultOAuth2WebClientHttpClient::class.java)
    override fun post(req: OAuth2HttpRequest) =
         with(req) {
             client.post()
                 .uri(tokenEndpointUrl)
                 .accept(APPLICATION_JSON)
                 .headers { c -> c.putAll(oAuth2HttpHeaders.headers()) }
                 .body(fromFormData(LinkedMultiValueMap<String, String>()
                     .apply { setAll(formParameters) }))
            .retrieve()
            .bodyToMono<OAuth2AccessTokenResponse>()
                 .doOnSuccess { log.info(" POST $tokenEndpointUrl OK $it") }
                 .doOnError { t: Throwable -> log.info(" POST $tokenEndpointUrl feilet", t) }
            .blockOptional()
                 .orElseThrow()  // or whatever
        }
}
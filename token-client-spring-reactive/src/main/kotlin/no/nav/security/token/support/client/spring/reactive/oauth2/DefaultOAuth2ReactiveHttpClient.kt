package no.nav.security.token.support.client.spring.reactive.oauth2

import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import org.springframework.web.reactive.function.client.WebClient

class DefaultOAuth2ReactiveHttpClient(var client: WebClient) :OAuth2HttpClient {
    override fun post(oAuth2HttpRequest: OAuth2HttpRequest?): OAuth2AccessTokenResponse {
        TODO("Not yet implemented")
    }
}
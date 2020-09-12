package no.nav.security.token.support.ktor.oauth

import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2CacheFactory
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfGrantRequest
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.ktor.http.DefaultOAuth2HttpClient
import no.nav.security.token.support.ktor.model.OAuth2Cache

@KtorExperimentalAPI
class OAuth2AccessTokenClient(
    private val config: ClientProperties,
    val cache: OAuth2Cache,
    tokenResolver: JwtBearerTokenResolver,
    val httpClient: DefaultOAuth2HttpClient
) {

    private val oauth2AccessTokenService: OAuth2AccessTokenService =
        OAuth2AccessTokenService(
            tokenResolver,
            OnBehalfOfTokenClient(httpClient),
            ClientCredentialsTokenClient(httpClient),
            TokenExchangeClient(httpClient)
        )

    init {
        // Set cache if enabled in configuration
        if (cache.enabled) {
            oauth2AccessTokenService.onBehalfOfGrantCache =
                OAuth2CacheFactory.accessTokenResponseCache<OnBehalfOfGrantRequest>(cache.maximumSize, cache.evictSkew)
        }
    }

    fun getAccessToken(): OAuth2AccessTokenResponse =
        oauth2AccessTokenService.getAccessToken(config)
}
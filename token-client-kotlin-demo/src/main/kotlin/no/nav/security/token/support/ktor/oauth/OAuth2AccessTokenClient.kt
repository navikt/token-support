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
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import java.util.*

@KtorExperimentalAPI
class OAuth2AccessTokenClient(
    private val clientConfig: ClientProperties,
    val cache: OAuth2Cache,
    private val client: ClientAssertion,
    val httpClient: DefaultOAuth2HttpClient
) : JwtBearerTokenResolver {

    private val oauth2AccessTokenService: OAuth2AccessTokenService =
        OAuth2AccessTokenService(
            this,
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

    // Override default client_assertion jwt, with specified Idp jwt
    override fun token(): Optional<String> {
        return Optional.of(client.assertion())
    }

    fun getAccessToken(): OAuth2AccessTokenResponse =
        oauth2AccessTokenService.getAccessToken(clientConfig)
}
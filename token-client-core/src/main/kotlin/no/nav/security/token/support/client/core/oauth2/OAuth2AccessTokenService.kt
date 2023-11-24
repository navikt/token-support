package no.nav.security.token.support.client.core.oauth2

import com.github.benmanes.caffeine.cache.Cache
import java.util.function.Function
import org.slf4j.LoggerFactory
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.CLIENT_CREDENTIALS
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.JWT_BEARER
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.TOKEN_EXCHANGE
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver

class OAuth2AccessTokenService @JvmOverloads constructor(private val tokenResolver : JwtBearerTokenResolver,
                               private val onBehalfOfTokenClient : OnBehalfOfTokenClient,
                               private val clientCredentialsTokenClient : ClientCredentialsTokenClient,
                               private val tokenExchangeClient : TokenExchangeClient,
                               var clientCredentialsGrantCache : Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse>? = null,
                               var exchangeGrantCache : Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse>? = null,
                               var onBehalfOfGrantCache : Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse>? = null) {



    fun getAccessToken(clientProperties : ClientProperties) : OAuth2AccessTokenResponse? {
        log.debug("Getting access_token for grant={}", clientProperties.grantType)
        return when (clientProperties.grantType) {
            JWT_BEARER -> executeOnBehalfOf(clientProperties)
            CLIENT_CREDENTIALS -> executeClientCredentials(clientProperties)
            TOKEN_EXCHANGE -> executeTokenExchange(clientProperties)
            else -> throw OAuth2ClientException("invalid grant-type=${clientProperties.grantType.value()} from OAuth2ClientConfig.OAuth2Client. grant-type not in supported grant-types ($SUPPORTED_GRANT_TYPES)")
        }
    }

    private fun executeOnBehalfOf(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(onBehalfOfGrantRequest(clientProperties), onBehalfOfGrantCache, onBehalfOfTokenClient::getTokenResponse)

    private fun executeTokenExchange(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(tokenExchangeGrantRequest(clientProperties), exchangeGrantCache, tokenExchangeClient::getTokenResponse)

    private fun executeClientCredentials(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(ClientCredentialsGrantRequest(clientProperties), clientCredentialsGrantCache, clientCredentialsTokenClient::getTokenResponse)

    private fun tokenExchangeGrantRequest(clientProperties : ClientProperties) =
        TokenExchangeGrantRequest(clientProperties, tokenResolver.token()
            .orElseThrow {
                OAuth2ClientException("no authenticated jwt token found in validation context, cannot do token exchange")
            })

    private fun onBehalfOfGrantRequest(clientProperties : ClientProperties) =
        OnBehalfOfGrantRequest(clientProperties, tokenResolver.token()
            .orElseThrow {
                OAuth2ClientException("no authenticated jwt token found in validation context, cannot do on-behalf-of")
            })

    override fun toString() =
        "${javaClass.getSimpleName()} [clientCredentialsGrantCache=$clientCredentialsGrantCache,  onBehalfOfGrantCache=$onBehalfOfGrantCache, tokenExchangeClient=$tokenExchangeClient, tokenResolver=$tokenResolver, onBehalfOfTokenClient=$onBehalfOfTokenClient, clientCredentialsTokenClient=$clientCredentialsTokenClient, exchangeGrantCache=$exchangeGrantCache]"
    companion object {

        private val SUPPORTED_GRANT_TYPES = listOf(JWT_BEARER, CLIENT_CREDENTIALS, TOKEN_EXCHANGE
                                                         )
        private val log = LoggerFactory.getLogger(OAuth2AccessTokenService::class.java)
        private fun <T : AbstractOAuth2GrantRequest?> getFromCacheIfEnabled(grantRequest : T, cache : Cache<T, OAuth2AccessTokenResponse>?,
                                                                            accessTokenResponseClient : Function<T, OAuth2AccessTokenResponse?>) =
            if (cache != null) {
                log.debug("cache is enabled so attempt to get from cache or update cache if not present.")
                cache[grantRequest, accessTokenResponseClient]
            }
            else {
                log.debug("cache is not set, invoke client directly")
                accessTokenResponseClient.apply(grantRequest)
            }
    }
}
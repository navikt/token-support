package no.nav.security.token.support.client.core.oauth2

import com.github.benmanes.caffeine.cache.Cache
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import java.util.function.Function
import org.slf4j.LoggerFactory
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver

class OAuth2AccessTokenService @JvmOverloads constructor(private val tokenResolver : JwtBearerTokenResolver,
                                                         private val onBehalfOfTokenClient : OnBehalfOfTokenClient,
                                                         private val clientCredentialsTokenClient : ClientCredentialsTokenClient,
                                                         private val tokenExchangeClient : TokenExchangeClient,
                                                         val clientCredentialsGrantCache : Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse>? = null,
                                                         val exchangeGrantCache : Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse>? = null,
                                                         val onBehalfOfGrantCache : Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse>? = null) {



    fun getAccessToken(p : ClientProperties) : OAuth2AccessTokenResponse {
        return when (p.grantType) {
            JWT_BEARER -> executeOnBehalfOf(p)
            CLIENT_CREDENTIALS -> executeClientCredentials(p)
            TOKEN_EXCHANGE -> executeTokenExchange(p)
            else -> throw OAuth2ClientException("Invalid grant-type ${p.grantType.value} from OAuth2ClientConfig.OAuth2Client. grant-type not in supported grant-types ($SUPPORTED_GRANT_TYPES)")
        }.also {
            log.debug("Got access_token for grant={}", p.grantType)
        }
    }

    private fun executeOnBehalfOf(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(onBehalfOfGrantRequest(clientProperties), onBehalfOfGrantCache, onBehalfOfTokenClient::getTokenResponse)

    private fun executeTokenExchange(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(tokenExchangeGrantRequest(clientProperties), exchangeGrantCache, tokenExchangeClient::getTokenResponse)

    private fun executeClientCredentials(clientProperties : ClientProperties) =
        getFromCacheIfEnabled(ClientCredentialsGrantRequest(clientProperties), clientCredentialsGrantCache, clientCredentialsTokenClient::getTokenResponse)

    private fun tokenExchangeGrantRequest(clientProperties : ClientProperties) =
        TokenExchangeGrantRequest(clientProperties, tokenResolver.token() ?: throw OAuth2ClientException("no authenticated jwt token found in validation context, cannot do token exchange"))

    private fun onBehalfOfGrantRequest(clientProperties : ClientProperties) =
        OnBehalfOfGrantRequest(clientProperties, tokenResolver.token() ?: throw OAuth2ClientException("no authenticated jwt token found in validation context, cannot do on-behalf-of"))

    override fun toString() = "${javaClass.getSimpleName()} [clientCredentialsGrantCache=$clientCredentialsGrantCache,  onBehalfOfGrantCache=$onBehalfOfGrantCache, tokenExchangeClient=$tokenExchangeClient, tokenResolver=$tokenResolver, onBehalfOfTokenClient=$onBehalfOfTokenClient, clientCredentialsTokenClient=$clientCredentialsTokenClient, exchangeGrantCache=$exchangeGrantCache]"
    companion object {

        private val SUPPORTED_GRANT_TYPES = listOf(JWT_BEARER, CLIENT_CREDENTIALS, TOKEN_EXCHANGE
                                                         )
        private val log = LoggerFactory.getLogger(OAuth2AccessTokenService::class.java)
        private fun <T : AbstractOAuth2GrantRequest?> getFromCacheIfEnabled(grantRequest : T, cache : Cache<T, OAuth2AccessTokenResponse>?, client : Function<T, OAuth2AccessTokenResponse>) =
            cache?.let {
                log.debug("Cache is enabled so attempt to get from cache or update cache if not present.")
                cache[grantRequest, client]
            } ?: client.apply(grantRequest)

    }
}
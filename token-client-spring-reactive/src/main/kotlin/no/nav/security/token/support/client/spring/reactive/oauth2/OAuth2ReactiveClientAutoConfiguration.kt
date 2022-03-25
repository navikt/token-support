package no.nav.security.token.support.client.spring.reactive.oauth2

import no.nav.security.token.support.client.core.OAuth2CacheFactory
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
import org.springframework.web.reactive.function.client.WebClient
import java.util.Optional



@EnableConfigurationProperties(ClientConfigurationProperties::class)
@Configuration
class OAuth2ReactiveClientAutoConfiguration {

    @Autowired
    private lateinit var env: Environment
        @Bean
        fun oAuth2ReactiveAccessTokenService(bearerTokenResolver: JwtBearerTokenResolver, client: OAuth2HttpClient) =
            OAuth2AccessTokenService(
                    bearerTokenResolver,
                    OnBehalfOfTokenClient(client),
                    ClientCredentialsTokenClient(client),
                    TokenExchangeClient(client)).apply {
                if (env.getProperty(PREFIX + "cacheEnabled",Boolean::class.java,false)) {
                    val max = env.getProperty(PREFIX + "cacheMaximumSize",Long::class.java,100)
                    val skew = env.getProperty(PREFIX +"cacheMaximumSize",Long::class.java,10)
                    clientCredentialsGrantCache = OAuth2CacheFactory.accessTokenResponseCache(max, skew)
                    onBehalfOfGrantCache = OAuth2CacheFactory.accessTokenResponseCache(max, skew)
                    exchangeGrantCache = OAuth2CacheFactory.accessTokenResponseCache(max, skew)
                } }

        @Bean
        fun oAuth2ReactiveHttpClient(b: WebClient.Builder) = DefaultOAuth2WebClientHttpClient(b.build())

        @Bean
        @ConditionalOnClass(TokenValidationContextHolder::class)
        fun jwtBearerTokenResolver(h: TokenValidationContextHolder) =
            JwtBearerTokenResolver {
                h.tokenValidationContext?.firstValidToken?.map { it.tokenAsString } ?: Optional.empty()
            }

    @Bean
    @ConditionalOnMissingBean(JwtBearerTokenResolver::class)
    @ConditionalOnMissingClass("no.nav.security.token.support.core.context.TokenValidationContextHolder")
    fun noopJwtBearerTokenResolver() =
        JwtBearerTokenResolver {
            throw UnsupportedOperationException("a no-op implementation of ${JwtBearerTokenResolver::class.java}  is registered, cannot get token to exchange required for OnBehalfOf/TokenExchange grant")
        }

    companion object {
        private const val PREFIX = "no.nav.security.token.support.client.spring.reactive."
    }
}
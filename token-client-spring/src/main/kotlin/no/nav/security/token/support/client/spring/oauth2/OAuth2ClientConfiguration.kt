package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.OAuth2CacheFactory.accessTokenResponseCache
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.ImportAware
import org.springframework.core.annotation.AnnotationAttributes
import org.springframework.core.annotation.AnnotationAttributes.fromMap
import org.springframework.core.type.AnnotationMetadata
import org.springframework.web.client.RestClient

@EnableConfigurationProperties(ClientConfigurationProperties::class)
@Configuration
class OAuth2ClientConfiguration : ImportAware {
    private val log = LoggerFactory.getLogger(OAuth2ClientConfiguration::class.java)
    private var attrs: AnnotationAttributes? = null
    override fun setImportMetadata(meta: AnnotationMetadata) {
        attrs = requireNotNull(fromMap(meta.getAnnotationAttributes(EnableOAuth2Client::class.java.name, false))) { "@EnableOAuth2Client is not present on importing class ${meta.className}" }
    }

    @Bean
    fun oAuth2ClientRequestInterceptor(properties: ClientConfigurationProperties, service: OAuth2AccessTokenService) = OAuth2ClientRequestInterceptor(properties, service)


    @Bean
    fun oAuth2AccessTokenService(bearerTokenResolver: JwtBearerTokenResolver, client: OAuth2HttpClient) =
        if (attrs?.getBoolean("cacheEnabled") == true) {
            log.trace("Caching is enabled")
            val maxx =  attrs?.getNumber<Long>("cacheMaximumSize") ?: 0
            val skew = attrs?.getNumber<Long>("cacheEvictSkew") ?: 0
            OAuth2AccessTokenService(bearerTokenResolver, OnBehalfOfTokenClient(client), ClientCredentialsTokenClient(client),
                TokenExchangeClient(client), accessTokenResponseCache(maxx, skew),
                accessTokenResponseCache(maxx, skew), accessTokenResponseCache(maxx, skew))
        }
        else  {
            OAuth2AccessTokenService(
                bearerTokenResolver,
                OnBehalfOfTokenClient(client),
                ClientCredentialsTokenClient(client),
                TokenExchangeClient(client))
        }


    @Bean
    @ConditionalOnMissingBean(OAuth2HttpClient::class)
    fun oAuth2HttpClient() = DefaultOAuth2HttpClient()

    @Bean
    @ConditionalOnClass(TokenValidationContextHolder::class)
    fun jwtBearerTokenResolver(h: TokenValidationContextHolder) =
        JwtBearerTokenResolver {
            h.getTokenValidationContext().firstValidToken?.encodedToken
        }

    @Bean
    @ConditionalOnMissingBean(JwtBearerTokenResolver::class)
    @ConditionalOnMissingClass("no.nav.security.token.support.core.context.TokenValidationContextHolder")
    fun noopJwtBearerTokenResolver() =
        JwtBearerTokenResolver {
            throw UnsupportedOperationException("A no-op implementation of ${JwtBearerTokenResolver::class.java}  is registered, cannot get token to exchange required for OnBehalfOf/TokenExchange grant")
        }
}

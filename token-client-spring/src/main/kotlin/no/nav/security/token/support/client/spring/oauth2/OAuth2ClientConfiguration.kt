package no.nav.security.token.support.client.spring.oauth2

import org.springframework.boot.context.properties.EnableConfigurationProperties
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import org.springframework.context.annotation.ImportAware
import org.springframework.core.type.AnnotationMetadata
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.client.core.OAuth2CacheFactory.*
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.AnnotationAttributes
import org.springframework.core.annotation.AnnotationAttributes.fromMap
import java.lang.UnsupportedOperationException
import java.util.Optional

@EnableConfigurationProperties(ClientConfigurationProperties::class)
@Configuration
class OAuth2ClientConfiguration : ImportAware {
    private var attrs: AnnotationAttributes? = null
    override fun setImportMetadata(meta: AnnotationMetadata) {
        attrs = fromMap(meta.getAnnotationAttributes(EnableOAuth2Client::class.java.name, false))
        requireNotNull(attrs) { "@EnableOAuth2Client is not present on importing class $meta.className" }
    }

    @Bean
    fun oAuth2AccessTokenService(bearerTokenResolver: JwtBearerTokenResolver, client: OAuth2HttpClient): OAuth2AccessTokenService {
        val service = OAuth2AccessTokenService(bearerTokenResolver, OnBehalfOfTokenClient(client), ClientCredentialsTokenClient(client), TokenExchangeClient(client))
        if (attrs?.getBoolean("cacheEnabled") == true) {
            val maximumSize = attrs!!.getNumber<Long>("cacheMaximumSize")
            val skewInSeconds = attrs!!.getNumber<Long>("cacheEvictSkew")
            service.clientCredentialsGrantCache = accessTokenResponseCache(maximumSize, skewInSeconds)
            service.onBehalfOfGrantCache = accessTokenResponseCache(maximumSize, skewInSeconds)
            service.setExchangeGrantCache(accessTokenResponseCache(maximumSize, skewInSeconds))
        }
        return service
    }

    @Bean
    fun oAuth2HttpClient(b: RestTemplateBuilder) = DefaultOAuth2HttpClient(b)

    @Bean
    @ConditionalOnClass(TokenValidationContextHolder::class)
    fun jwtBearerTokenResolver(h: TokenValidationContextHolder)  =
         JwtBearerTokenResolver {
            h.tokenValidationContext?.firstValidToken?.map{ obj -> obj.tokenAsString  } ?: Optional.empty()
        }

    @Bean
    @ConditionalOnMissingBean(JwtBearerTokenResolver::class)
    @ConditionalOnMissingClass("no.nav.security.token.support.core.context.TokenValidationContextHolder")
    fun noopJwtBearerTokenResolver() =
         JwtBearerTokenResolver {
            throw UnsupportedOperationException("a no-op implementation of ${JwtBearerTokenResolver::class.java}  is registered, cannot get token to exchange required for OnBehalfOf/TokenExchange grant")
        }
}
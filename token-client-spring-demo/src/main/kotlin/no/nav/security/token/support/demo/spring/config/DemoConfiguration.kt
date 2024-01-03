package no.nav.security.token.support.demo.spring.config

import org.springframework.boot.web.client.RestClientCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.client.spring.oauth2.ClientConfigurationPropertiesMatcher
import no.nav.security.token.support.client.spring.oauth2.EnableOAuth2Client
import no.nav.security.token.support.client.spring.oauth2.OAuth2ClientRequestInterceptor
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation

/***
 * You may only need one rest client if the short name in the config matches the canonical
 * hostname of the remote service. If not, you will need one rest client per remote service.
 * The rest client is configured with a base url, and the rest client customizer is used to register
 * a filter that will exchange add the access token to the request.
 *
 */
@EnableOAuth2Client(cacheEnabled = true)
@EnableJwtTokenValidation
@Configuration
class DemoConfiguration {
    @Bean
    fun customizer(reqInterceptor : OAuth2ClientRequestInterceptor) = RestClientCustomizer { it.requestInterceptor(reqInterceptor) }

    @Bean
    fun requestInterceptor(properties : ClientConfigurationProperties, service : OAuth2AccessTokenService, matcher : ClientConfigurationPropertiesMatcher) = OAuth2ClientRequestInterceptor(properties, service, matcher)

    @Bean
    fun configMatcher() = object: ClientConfigurationPropertiesMatcher{}
}
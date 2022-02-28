package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse

/**
 *
 * Interceptor that exchanges a token using the [OAuth2AccessTokenService]
 * and sets Authorization header to this new token, where the aud claim is set
 * to the destination app. The configuration fo this app is retrieved through a
 * configurable matcher implementing
 * [ClientConfigurationPropertiesMatcher]. If no configuration is found,
 * this interceptor is NOOP. This intercptor must be registered by the applications themselves,
 * there is no automatic bean registration.
 *
 */
class OAuth2ClientRequestInterceptor(private val properties: ClientConfigurationProperties,
                                     private val service: OAuth2AccessTokenService,
                                     private val matcher: ClientConfigurationPropertiesMatcher) : ClientHttpRequestInterceptor {
    override fun intercept(req: HttpRequest, body: ByteArray, execution: ClientHttpRequestExecution): ClientHttpResponse {
        matcher.findProperties(properties, req.uri).orElse(null)
            ?.let { req.headers.setBearerAuth(service.getAccessToken(it).accessToken) }
        return execution.execute(req, body)
    }

    override fun toString() = "$javaClass.simpleName  [properties=$properties, service=$service, matcher=$matcher]"

}
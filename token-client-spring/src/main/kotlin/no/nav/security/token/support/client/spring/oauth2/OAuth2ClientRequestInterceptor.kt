package no.nav.security.token.support.client.spring.oauth2

import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties

/**
 *
 * Interceptor that exchanges a token using the [OAuth2AccessTokenService]
 * and sets the Authorization header to this new token, where the aud claim is set
 * to the destination app. The configuration fo this app is retrieved through a
 * configurable matcher implementing
 * [ClientConfigurationPropertiesMatcher]. If no configuration is found,
 * the interceptor is NOOP. The same applies if there is no Authorization header present, as there will be nothing to exchange in that case.
 * This again means that the interceptor can be safely registered on clients used for unauthenticated calls, such as pings/healthchecks.
 * This intercptor must be registered by the applications themselves, there is no automatic bean registration.
 *
 */
class OAuth2ClientRequestInterceptor(private val properties: ClientConfigurationProperties,
                                     private val service: OAuth2AccessTokenService,
                                     private val matcher: ClientConfigurationPropertiesMatcher) : ClientHttpRequestInterceptor {
    override fun intercept(req: HttpRequest, body: ByteArray, execution: ClientHttpRequestExecution): ClientHttpResponse {
        matcher.findProperties(properties, req.uri)?.let {
            service.getAccessToken(it)?.accessToken?.let { it1 -> req.headers.setBearerAuth(it1) }
        }
        return execution.execute(req, body)
    }

    override fun toString() = "$javaClass.simpleName  [properties=$properties, service=$service, matcher=$matcher]"

}
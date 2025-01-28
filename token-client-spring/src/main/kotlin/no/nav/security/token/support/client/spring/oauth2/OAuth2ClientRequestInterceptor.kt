package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import org.slf4j.LoggerFactory
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse

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
                                     private val matcher: ClientConfigurationPropertiesMatcher =  object : ClientConfigurationPropertiesMatcher {}) : ClientHttpRequestInterceptor {

    private val log = LoggerFactory.getLogger(OAuth2ClientRequestInterceptor::class.java)


    override fun intercept(req: HttpRequest, body: ByteArray, execution: ClientHttpRequestExecution): ClientHttpResponse {
        log.trace("Intercepting request to {}", req.uri)
        matcher.findProperties(properties, req.uri)?.let {
            log.trace("Found properties for uri {}", req.uri)
            service.getAccessToken(it).access_token?.let {
                token -> req.headers.setBearerAuth(token)
                log.trace("Finished setting access token in authorization header OK for uri {}", req.uri)
            }
        }
        return execution.execute(req, body)
    }
    override fun toString() = "${javaClass.simpleName}  [properties=$properties, service=$service, matcher=$matcher]"

}
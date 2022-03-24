package no.nav.security.token.support.client.spring.reactive.oauth2

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.client.spring.oauth2.ClientConfigurationPropertiesMatcher
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.http.HttpHeaders.AUTHORIZATION
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.ExchangeFunction
import reactor.core.publisher.Mono

class OAuth2ExchangeFilterFunction(
private val configs: ClientConfigurationProperties,
private val service: OAuth2AccessTokenService,
private val matcher: ClientConfigurationPropertiesMatcher,
private val holder: TokenValidationContextHolder) : ExchangeFilterFunction {

    override fun filter(req: ClientRequest, next: ExchangeFunction): Mono<ClientResponse> {
        if (holder.tokenValidationContext.hasValidToken()) {
            return matcher.findProperties(configs, req.url()).orElse(null)
                ?.let {
                    next.exchange(ClientRequest.from(req).header(AUTHORIZATION, service.getAccessTokenAsBearer(it)).build())
                } ?: noExchange(next, req)
        }
        return noExchange(next, req)
    }

    private fun noExchange(next: ExchangeFunction, req: ClientRequest) = next.exchange(ClientRequest.from(req).build())
    override fun toString() = "${javaClass.simpleName} [[configs=$configs,service=$service,matcher=$matcher]"
}
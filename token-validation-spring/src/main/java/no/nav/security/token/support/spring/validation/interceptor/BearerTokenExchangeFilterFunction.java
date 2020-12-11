package no.nav.security.token.support.spring.validation.interceptor;

import static no.nav.security.token.support.spring.validation.interceptor.TokenUtil.authorizationTokens;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import reactor.core.publisher.Mono;

public class BearerTokenExchangeFilterFunction implements ExchangeFilterFunction {

    private final TokenValidationContextHolder holder;

    public BearerTokenExchangeFilterFunction(TokenValidationContextHolder holder) {
        this.holder = holder;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest req, ExchangeFunction next) {
        var builder = ClientRequest.from(req);
        authorizationTokens(holder).ifPresent(t -> builder.header(AUTHORIZATION, t));
        return next.exchange(builder.build());
    }
}
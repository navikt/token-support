package no.nav.security.token.support.spring.validation.interceptor;

import static no.nav.security.token.support.spring.validation.interceptor.TokenUtil.authorizationTokens;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.io.IOException;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;

public class BearerTokenClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final TokenValidationContextHolder holder;

    public BearerTokenClientHttpRequestInterceptor(TokenValidationContextHolder holder) {
        this.holder = holder;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {

        authorizationTokens(holder).ifPresent(t -> request.getHeaders().add(AUTHORIZATION, t));
        return execution.execute(request, body);
    }
}

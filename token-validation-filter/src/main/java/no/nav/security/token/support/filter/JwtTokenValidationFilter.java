package no.nav.security.token.support.filter;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.http.HttpRequest;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

public class JwtTokenValidationFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenValidationFilter.class);
    private final JwtTokenValidationHandler jwtTokenValidationHandler;
    private final TokenValidationContextHolder contextHolder;

    public JwtTokenValidationFilter(JwtTokenValidationHandler jwtTokenValidationHandler, TokenValidationContextHolder contextHolder) {
        this.jwtTokenValidationHandler = jwtTokenValidationHandler;
        this.contextHolder = contextHolder;
    }

    @Override
    public void destroy() {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            doTokenValidation((HttpServletRequest) request, (HttpServletResponse) response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    private void doTokenValidation(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        contextHolder.setTokenValidationContext(jwtTokenValidationHandler.getValidatedTokens(fromHttpServletRequest(request)));
        try {
            chain.doFilter(request, response);
        } finally {
            contextHolder.setTokenValidationContext(null);
        }
    }

    static HttpRequest fromHttpServletRequest(final HttpServletRequest request) {
        return new HttpRequest() {
            @Override
            public String getHeader(String headerName) {
                return request.getHeader(headerName);
            }

            @Override
            public NameValue[] getCookies() {
                if (request.getCookies() == null) {
                    return null;
                }
                return Arrays.stream(request.getCookies()).map(cookie -> new NameValue() {

                    @Override
                    public String getName() {
                        return cookie.getName();
                    }

                    @Override
                    public String getValue() {
                        return cookie.getValue();
                    }
                }).toArray(NameValue[]::new);
            }
        };
    }

}

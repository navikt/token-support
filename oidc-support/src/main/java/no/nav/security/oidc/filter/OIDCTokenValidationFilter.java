package no.nav.security.oidc.filter;

import static no.nav.security.oidc.http.HTTPTokenValidator.validateTokensAndCreateContext;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.http.TokenRetriever;
import no.nav.security.oidc.http.TokenRetriever.NameValue;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

public class OIDCTokenValidationFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(OIDCTokenValidationFilter.class);
    private final MultiIssuerConfiguration config;
    private final OIDCRequestContextHolder contextHolder;

    public OIDCTokenValidationFilter(MultiIssuerConfiguration oidcConfig, OIDCRequestContextHolder contextHolder) {
        this.config = oidcConfig;
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
        }
        else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    private void doTokenValidation(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        contextHolder.setOIDCValidationContext(validateTokensAndCreateContext(config, fromHttpServletRequest(request)));
        try {
            chain.doFilter(request, response);
        } finally {
            contextHolder.setOIDCValidationContext(null);
        }
    }

    static TokenRetriever.HttpRequest fromHttpServletRequest(final HttpServletRequest request) {
        return new TokenRetriever.HttpRequest() {
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

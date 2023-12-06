package no.nav.security.token.support.jaxrs;

import jakarta.inject.Inject;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Collections.singletonList;

public class JwtTokenClientRequestFilter implements ClientRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenClientRequestFilter.class);

    @Inject
    public JwtTokenClientRequestFilter() { }

    @Override
    public void filter(ClientRequestContext requestContext) {

        TokenValidationContext context = JaxrsTokenValidationContextHolder.getHolder().getTokenValidationContext();

        if(context.hasValidToken()) {
            LOG.debug("adding tokens to Authorization header");
            StringBuilder headerValue = new StringBuilder();
            context.getIssuers().forEach(issuer -> {
                LOG.debug("adding token for issuer {}", issuer);
                headerValue.append("Bearer ").append(context.getJwtToken(issuer).getTokenAsString());
            });
            requestContext.getHeaders().put(JwtTokenConstants.AUTHORIZATION_HEADER, singletonList(headerValue.toString()));
        } else {
            LOG.debug("no tokens found, nothing added to request");
        }
    }

}
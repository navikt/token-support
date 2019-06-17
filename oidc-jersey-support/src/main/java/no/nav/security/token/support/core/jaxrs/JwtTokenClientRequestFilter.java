package no.nav.security.token.support.core.jaxrs;

import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;

import static java.util.Collections.singletonList;

public class JwtTokenClientRequestFilter implements ClientRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenClientRequestFilter.class);

    @Inject
    public JwtTokenClientRequestFilter() { }

    @Override
    public void filter(ClientRequestContext requestContext) {

        TokenValidationContext context = JaxrsTokenValidationContextHolder.getHolder().getTokenValidationContext();

        if(context != null && context.hasValidToken()) {
            logger.debug("adding tokens to Authorization header");
            StringBuilder headerValue = new StringBuilder();
            for(String issuer : context.getIssuers()) {
                logger.debug("adding token for issuer {}", issuer);
                headerValue.append("Bearer ").append(context.getJwtToken(issuer).getTokenAsString());
            }
            requestContext.getHeaders().put(JwtTokenConstants.AUTHORIZATION_HEADER, singletonList(headerValue.toString()));
        } else {
            logger.debug("no tokens found, nothing added to request");
        }
    }

}

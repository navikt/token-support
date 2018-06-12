package no.nav.security.oidc.jaxrs;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.context.OIDCValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import java.io.IOException;

import static java.util.Collections.singletonList;

// Should considering making it completely spring free.. It is not possible to make it spring free while also keepign
// the filters spring enabled. Spring will not inject the request scoped variables (ResourceInfo) correctly if
// @Scope + @Component is removed
// TODO or can it be configured with the @Bean annotation - as long as the class isn't autodiscovered/scanned
@Component
public class OidcClientRequestFilter implements ClientRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(OidcClientRequestFilter.class);

    @Inject
    public OidcClientRequestFilter() { }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {

        OIDCValidationContext context = OidcRequestContext.getHolder().getOIDCValidationContext();

        if(context != null) {
            logger.debug("adding tokens to Authorization header");
            StringBuilder headerValue = new StringBuilder();
            for(String issuer : context.getIssuers()) {
                logger.debug("adding token for issuer {}", issuer);
                headerValue.append("Bearer ").append(context.getToken(issuer).getIdToken());
            }
            requestContext.getHeaders().put(OIDCConstants.AUTHORIZATION_HEADER, singletonList(headerValue.toString()));
        } else {
            logger.debug("no tokens found, nothing added to request");
        }
    }

}

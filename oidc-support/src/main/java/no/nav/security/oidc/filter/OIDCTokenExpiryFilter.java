package no.nav.security.oidc.filter;

import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Checks the expiry time in a validated token against a preconfigured threshold
 * and returns a custom http header if this threshold is reached.
 * <p>
 * Can be used to check if the token is about to expire and inform the caller
 */
public class OIDCTokenExpiryFilter implements Filter {

    public static final String TOKEN_EXPIRES_SOON_HEADER = "x-token-expires-soon";

    private static final Logger log = LoggerFactory.getLogger(OIDCTokenExpiryFilter.class);
    private final OIDCRequestContextHolder contextHolder;
    private final long expiryThresholdInMinutes;

    public OIDCTokenExpiryFilter(OIDCRequestContextHolder contextHolder, long expiryThresholdInMinutes) {
        this.contextHolder = contextHolder;
        this.expiryThresholdInMinutes = expiryThresholdInMinutes;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            addHeaderOnTokenExpiryThreshold((HttpServletResponse)response);
            chain.doFilter(request, response);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() { }

    @Override
    public void init(FilterConfig filterConfig) { }

    private void addHeaderOnTokenExpiryThreshold(HttpServletResponse response){
        OIDCValidationContext oidcValidationContext = contextHolder.getOIDCValidationContext();
        log.debug("getting OIDCValidationContext: {}",oidcValidationContext);
        if(oidcValidationContext != null){
            log.debug("getting issuers from validationcontext {}", oidcValidationContext.getIssuers());
            for (String issuer : oidcValidationContext.getIssuers()) {
                OIDCClaims oidcClaims = oidcValidationContext.getClaims(issuer);
                if(tokenExpiresBeforeThreshold(oidcClaims)){
                    log.debug("setting response header {}", TOKEN_EXPIRES_SOON_HEADER);
                    response.setHeader(TOKEN_EXPIRES_SOON_HEADER, "true");
                } else {
                    log.debug("token is still within expiry threshold.");
                }
            }
        }
    }

    private boolean tokenExpiresBeforeThreshold(OIDCClaims oidcClaims){
        Date expiryDate = oidcClaims.getClaimSet().getExpirationTime();
        LocalDateTime expiry = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault());
        long minutesUntilExpiry = LocalDateTime.now().until(expiry, ChronoUnit.MINUTES);
        log.debug("checking token at time {} with expirationTime {} for how many minutes until expiry: {}",LocalDateTime.now(), expiry, minutesUntilExpiry);
        if(minutesUntilExpiry <= expiryThresholdInMinutes){
            log.debug("there are {} minutes until expiry which is equal to or less than the configured threshold {}", minutesUntilExpiry, expiryThresholdInMinutes);
            return true;
        }
       return false;
    }
}

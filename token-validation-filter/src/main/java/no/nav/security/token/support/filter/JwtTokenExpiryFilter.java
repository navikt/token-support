package no.nav.security.token.support.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.nav.security.token.support.core.jwt.JwtTokenClaims;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;

/**
 * Checks the expiry time in a validated token against a preconfigured threshold
 * and returns a custom http header if this threshold is reached.
 * <p>
 * Can be used to check if the token is about to expire and inform the caller
 */
public class JwtTokenExpiryFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenExpiryFilter.class);
    private final TokenValidationContextHolder contextHolder;
    private final long expiryThresholdInMinutes;

    public JwtTokenExpiryFilter(TokenValidationContextHolder contextHolder, long expiryThresholdInMinutes) {
        this.contextHolder = contextHolder;
        this.expiryThresholdInMinutes = expiryThresholdInMinutes;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            addHeaderOnTokenExpiryThreshold((HttpServletResponse) response);
            chain.doFilter(request, response);
        }
        else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    private void addHeaderOnTokenExpiryThreshold(HttpServletResponse response) {
        var tokenValidationContext = contextHolder.getTokenValidationContext();
        LOG.debug("Getting TokenValidationContext: {}", tokenValidationContext);
        if (tokenValidationContext != null) {
            LOG.debug("Getting issuers from validationcontext {}", tokenValidationContext.getIssuers());
            for (String issuer : tokenValidationContext.getIssuers()) {
                var jwtTokenClaims = tokenValidationContext.getClaims(issuer);
                if (tokenExpiresBeforeThreshold(jwtTokenClaims)) {
                    LOG.debug("Setting response header {}", JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER);
                    response.setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true");
                }
                else {
                    LOG.debug("Token is still within expiry threshold.");
                }
            }
        }
    }

    private boolean tokenExpiresBeforeThreshold(JwtTokenClaims jwtTokenClaims) {
        Date expiryDate = (Date)jwtTokenClaims.get("exp");
        LocalDateTime expiry = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault());
        long minutesUntilExpiry = LocalDateTime.now().until(expiry, ChronoUnit.MINUTES);
        LOG.debug("Checking token at time {} with expirationTime {} for how many minutes until expiry: {}",
                LocalDateTime.now(), expiry, minutesUntilExpiry);
        if (minutesUntilExpiry <= expiryThresholdInMinutes) {
            LOG.debug("There are {} minutes until expiry which is equal to or less than the configured threshold {}",
                    minutesUntilExpiry, expiryThresholdInMinutes);
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [contextHolder=" + contextHolder + ", expiryThresholdInMinutes="
                + expiryThresholdInMinutes + "]";
    }
}

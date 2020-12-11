package no.nav.security.token.support.spring.validation.interceptor;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;

final class TokenUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);

    private TokenUtil() {

    }

    static Optional<String> authorizationTokens(TokenValidationContextHolder holder) {
        var context = holder.getTokenValidationContext();
        if (context != null && context.hasValidToken()) {
            LOGGER.debug("Adding tokens to Authorization header");
            StringBuilder headerValue = new StringBuilder();
            boolean first = true;
            for (String issuer : context.getIssuers()) {
                LOGGER.debug("Adding token for issuer {}", issuer);
                if (!first) {
                    headerValue.append(",");
                }
                headerValue.append("Bearer " + context.getJwtToken(issuer).getTokenAsString());
                first = false;
            }
            return Optional.of(headerValue.toString());
        } else {
            LOGGER.debug("No tokens found, nothing added to request");
            return Optional.empty();
        }
    }
}

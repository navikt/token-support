package no.nav.security.token.support.core.utils;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.jwt.JwtToken;

import java.util.Optional;

public class JwtTokenUtil {

    public static boolean contextHasValidToken(TokenValidationContextHolder tokenValidationContextHolder){
        return tokenValidationContext(tokenValidationContextHolder)
            .map(TokenValidationContext::hasValidToken)
            .orElse(false);
    }

    public static Optional<JwtToken> getJwtToken(String issuer, TokenValidationContextHolder tokenValidationContextHolder){
        return tokenValidationContext(tokenValidationContextHolder).map(ctx -> ctx.getJwtToken(issuer));
    }

    private static Optional<TokenValidationContext> tokenValidationContext(TokenValidationContextHolder tokenValidationContextHolder){
        if(tokenValidationContextHolder == null){
            throw new IllegalStateException("{} cannot be null, check your configuration.");
        }
        return Optional.ofNullable(tokenValidationContextHolder.getTokenValidationContext());
    }
}

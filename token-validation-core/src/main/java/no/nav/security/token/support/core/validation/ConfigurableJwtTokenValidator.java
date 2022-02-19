package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class ConfigurableJwtTokenValidator implements JwtTokenValidator {

    private final String issuer;
    private final RemoteJWKSet<SecurityContext> remoteJWKSet;
    private final List<String> defaultRequiredClaims = List.of("sub", "aud", "iss", "iat", "exp", "nbf");
    private final List<String> requiredClaims;

    public ConfigurableJwtTokenValidator(
        String issuer,
        List<String> optionalClaims,
        RemoteJWKSet<SecurityContext> remoteJWKSet
    ) {
        this.issuer = issuer;
        this.remoteJWKSet = remoteJWKSet;
        this.requiredClaims = removeOptionalClaims(
            defaultRequiredClaims,
            Optional.ofNullable(optionalClaims).orElse(Collections.emptyList())
        );
    }

    @Override
    public void assertValidToken(String tokenString) throws JwtTokenValidatorException {
        verify(issuer, tokenString,
            new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                remoteJWKSet
            )
        );
    }

    private void verify(String issuer, String tokenString, JWSVerificationKeySelector<SecurityContext> keySelector) {
        verify(
            tokenString,
            new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .build(),
                new HashSet<>(requiredClaims)
            ),
            keySelector
        );
    }

    private void verify(String tokenString, JWTClaimsSetVerifier<SecurityContext> jwtClaimsSetVerifier, JWSVerificationKeySelector<SecurityContext> keySelector) {
        try {
            var  jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(keySelector);
            jwtProcessor.setJWTClaimsSetVerifier(jwtClaimsSetVerifier);
            var token = parse(tokenString);
            jwtProcessor.process(token, null);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token validation failed: " + t.getMessage(), t);
        }
    }

    private static <T> List<T> removeOptionalClaims(List<T> first, List<T> second) {
        return first.stream()
            .filter(c -> !second.contains(c))
            .collect(Collectors.toList());
    }

    private JWT parse(String tokenString) {
        try {
            return JWTParser.parse(tokenString);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token verification failed: " + t.getMessage(), t);
        }
    }

    protected RemoteJWKSet<SecurityContext> getRemoteJWKSet() {
        return this.remoteJWKSet;
    }
}

package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import no.nav.security.token.support.core.configuration.IssuerProperties;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;

import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class ConfigurableJwtTokenValidator implements JwtTokenValidator {

    private final String issuer;
    private final RemoteJWKSet<SecurityContext> remoteJWKSet;
    private final List<String> defaultRequiredClaims = List.of("sub", "aud", "iss", "iat", "exp", "nbf");
    private final List<String> requiredClaims;

    public ConfigurableJwtTokenValidator(
        String issuer,
        URL jwkSetUrl,
        ResourceRetriever resourceRetriever,
        List<String> optionalClaims,
        IssuerProperties.JwkSetCache jwkSetCache
    ) {
        this.issuer = issuer;
        this.remoteJWKSet = configureJWKSetCache(jwkSetUrl, resourceRetriever, jwkSetCache);
        this.requiredClaims = filterList(
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
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(keySelector);
            jwtProcessor.setJWTClaimsSetVerifier(jwtClaimsSetVerifier);
            JWT token = parse(tokenString);
            jwtProcessor.process(token, null);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token validation failed: " + t.getMessage(), t);
        }
    }

    private static <T> List<T> filterList(List<T> first, List<T> second) {
        return first.stream()
            .filter(c -> !second.contains(c))
            .collect(Collectors.toList());
    }

    private RemoteJWKSet<SecurityContext> configureJWKSetCache(
        URL jwkSetUrl,
        ResourceRetriever resourceRetriever,
        IssuerProperties.JwkSetCache jwkSetCache
    ) {
        return jwkSetCache.isConfigured() ? new RemoteJWKSet<>(
            jwkSetUrl,
            resourceRetriever,
            new DefaultJWKSetCache(
                jwkSetCache.getLifespan(),
                jwkSetCache.getRefreshTime(),
                TimeUnit.MINUTES
            )
        ) : new RemoteJWKSet<>(jwkSetUrl, resourceRetriever);
    }

    private JWT parse(String tokenString) {
        try {
            return JWTParser.parse(tokenString);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token verification failed: " + t.getMessage(), t);
        }
    }
}

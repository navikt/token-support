package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
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
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;

import java.net.URL;
import java.util.HashSet;
import java.util.List;

public class ConfigurableJwtTokenValidator implements JwtTokenValidator {

    private final String issuer;
    private final RemoteJWKSet<SecurityContext> remoteJWKSet;
    private final List<String> requiredClaims = List.of("iss", "iat", "exp", "nbf");

    public ConfigurableJwtTokenValidator(String issuer, URL jwkSetUrl, ResourceRetriever resourceRetriever) {
        this.issuer = issuer;
        remoteJWKSet = new RemoteJWKSet<>(jwkSetUrl, resourceRetriever);
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
            throw new JwtTokenValidatorException("Token validation failed: " + t.getMessage());
        }
    }

    private JWT parse(String tokenString) {
        try {
            return JWTParser.parse(tokenString);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token verification failed: " + t.getMessage());
        }
    }
}

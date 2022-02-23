package no.nav.security.token.support.core.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtTokenAnnotationHandlerTest {

    private final JwtTokenAnnotationHandler annotationHandler;

    private static final JwtToken T1 = jwtToken("https://one", "acr=Level3");
    private static final JwtToken T2 = jwtToken("https://two", "acr=Level4");
    private static final JwtToken T3 = jwtToken("https://three", "acr=Level1");
    private static final JwtToken T4 = jwtToken("https://four", "acr=Level3", "foo=bar");

    public JwtTokenAnnotationHandlerTest() {
        Map<String, JwtToken> validationContextMap = new HashMap<>();

        validationContextMap.put("issuer1", T1);
        validationContextMap.put("issuer2", T2);
        validationContextMap.put("issuer3", T3);
        validationContextMap.put("issuer4", T4);

        TokenValidationContext tvc = new TokenValidationContext(validationContextMap);
        TokenValidationContextHolder tokenValidationContextHolder = new TokenValidationContextHolder() {
            @Override
            public TokenValidationContext getTokenValidationContext() {
                return tvc;
            }

            @Override
            public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
            }
        };
        this.annotationHandler = new JwtTokenAnnotationHandler(tokenValidationContextHolder);
    }

    @Test
    public void checkThatAlternativeClaimsWithSameKeyWorks() {
        final String[] protectedWithAnyClaim = new String[] { "acr=Level3", "acr=Level4" }; // Require either acr=Level3 or acr=Level4

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAnyClaim, true, T1));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAnyClaim, true, T2));

        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAnyClaim, true, T3));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAnyClaim, true,
                T4));
    }

    @Test
    public void checkThatMultipleRequiredClaimsWorks() {
        final String[] protectedWithAllClaims = new String[] { "acr=Level3", "foo=bar" }; // Require acr=Level3 and foo=bar

        assertFalse(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAllClaims, false, T1));
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAllClaims, false, T2));
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAllClaims, false, T3));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAllClaims, false, T4));
    }

    @Test
    public void checkThatClaimWithUnknownValueIsRejected() {
        final String[] protectedWithClaims = new String[] { "acr=Level3", "acr=Level4" };

        // Token from issuer3 only contains acr=Level1
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true, T3));
        assertFalse(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false, T3));
    }

    @Test
    public void chechThatNoReqiredClaimsWorks() {
        final String[] protectedWithClaims = new String[0];

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, true, T1));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, true, T2));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true, T3));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, true, T4));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, false, T1));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, false, T2));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false, T3));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, false, T4));
    }

    private static JwtToken jwtToken(String issuer, String... claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("subject");
        Arrays.stream(claims).map(c -> c.split("=")).forEach(pair -> {
            builder.claim(pair[0], pair[1]);
        });
        PlainJWT plainJWT = new PlainJWT(builder.build());
        return new JwtToken(plainJWT.serialize());
    }

}

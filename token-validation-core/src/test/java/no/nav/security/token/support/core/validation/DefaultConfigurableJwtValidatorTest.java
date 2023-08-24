package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class DefaultConfigurableJwtValidatorTest extends AbstractJwtValidatorTest {
    private final URL jwksUrl = new URL("https://someurl");
    private final JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl, new MockResourceRetriever()).build();

    DefaultConfigurableJwtValidatorTest() throws MalformedURLException {
    }

    @Test
    void happyPath() throws JwtTokenValidatorException {
        var validator = tokenValidator(Collections.singletonList("aud1"));
        validator.assertValidToken(token("aud1"));
    }

    @Test
    void happyPathWithOptionalClaims() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.singletonList("aud1");
        var optionalClaims = List.of(JWTClaimNames.SUBJECT, JWTClaimNames.AUDIENCE);
        var validator = tokenValidator(acceptedAudiences, optionalClaims);

        validator.assertValidToken(token("aud1"));
        validator.assertValidToken(token("not-aud1"));
        validator.assertValidToken(token(Collections.emptyList()));
        validator.assertValidToken(token(defaultClaims().build()));
        validator.assertValidToken(token(defaultClaims().audience((String) null).build()));
        validator.assertValidToken(token(defaultClaims().audience(Collections.emptyList()).subject(null).build()));
        validator.assertValidToken(token(defaultClaims().subject(null).build()));
    }

    @Test
    void missingRequiredClaims() throws JwtTokenValidatorException {
        var aud = Collections.singletonList("aud1");
        var validator = tokenValidator(aud);

        assertThrows(JwtTokenValidatorException.class, () -> {
            var claims = defaultClaims()
                .issuer(null)
                .audience(aud)
                .build();
            validator.assertValidToken(token(claims));
        }, "missing default required issuer claim");

        assertThrows(JwtTokenValidatorException.class, () -> {
            var claims = defaultClaims()
                .subject(null)
                .audience(aud)
                .build();
            validator.assertValidToken(token(claims));
        }, "missing default required subject claim");

        assertThrows(JwtTokenValidatorException.class, () -> {
            var claims = defaultClaims()
                .audience(Collections.emptyList())
                .build();
            validator.assertValidToken(token(claims));
        }, "missing default required audience claim");

        assertThrows(JwtTokenValidatorException.class, () -> {
            var claims = defaultClaims()
                .audience(aud)
                .expirationTime(null)
                .build();
            validator.assertValidToken(token(claims));
        }, "missing default required expiration time claim");

        assertThrows(JwtTokenValidatorException.class, () -> {
            var claims = defaultClaims()
                .audience(aud)
                .issueTime(null)
                .build();
            validator.assertValidToken(token(claims));
        }, "missing default required issued at claim");
    }

    @Test
    void atLeastOneAudienceMustMatch() throws JwtTokenValidatorException {
        var validator = tokenValidator(Collections.singletonList("aud1"));
        validator.assertValidToken(token("aud1"));
        validator.assertValidToken(token(List.of("aud1", "aud2")));
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token(List.of("aud2", "aud3"))), "at least one audience must match accepted audiences");
    }

    @Test
    void multipleAcceptedAudiences() throws JwtTokenValidatorException {
        var acceptedAudiences = List.of("aud1", "aud2");
        var validator = tokenValidator(acceptedAudiences);
        validator.assertValidToken(token("aud1"));
        validator.assertValidToken(token("aud2"));
        validator.assertValidToken(token(List.of("aud1", "aud2")));
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token("aud3")), "unknown audience should be rejected");
    }

    @Test
    void noAcceptedAudiences() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.<String>emptyList();
        var validator = tokenValidator(acceptedAudiences);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token("aud1")), "unknown audience should be rejected");
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token(Collections.emptyList())), "missing required audience claim");
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token((String) null)), "missing required audience claim");
    }

    @Test
    void noAcceptedAudiencesWithOptionalClaimShouldAcceptAnyAudience() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.<String>emptyList();
        var optionalClaims = Collections.singletonList(JWTClaimNames.AUDIENCE);
        var validator = tokenValidator(acceptedAudiences, optionalClaims);
        validator.assertValidToken(token("aud1"));
        validator.assertValidToken(token("aud2"));
    }

    @Test
    void issuerMismatch() throws JwtTokenValidatorException {
        var aud = Collections.singletonList("aud1");
        var validator = tokenValidator(aud);
        assertThrows(JwtTokenValidatorException.class, () -> {
            var token = token(defaultClaims()
                .audience(aud)
                .issuer("invalid-issuer")
                .build());
            validator.assertValidToken(token);
        });
    }

    @Test
    void missingNbfShouldNotFail() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.singletonList("aud1");
        var validator = tokenValidator(acceptedAudiences);
        var token = token(defaultClaims()
            .audience(acceptedAudiences)
            .notBeforeTime(null)
            .build());
        validator.assertValidToken(token);
    }

    @Test
    void expBeforeNowShouldFail() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.singletonList("aud1");
        var validator = tokenValidator(acceptedAudiences);
        var now = new Date();
        var beforeNow = new Date(now.getTime() - maxClockSkewMillis());
        var token = token(defaultClaims()
            .audience(acceptedAudiences)
            .expirationTime(beforeNow)
            .build());
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token));
    }

    @Test
    void iatAfterNowShouldFail() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.singletonList("aud1");
        var validator = tokenValidator(acceptedAudiences);
        var now = new Date();
        var afterNow = new Date(now.getTime() + maxClockSkewMillis());
        var token = token(defaultClaims()
            .audience(acceptedAudiences)
            .issueTime(afterNow)
            .build());
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token));
    }

    @Test
    void nbfAfterNowShouldFail() throws JwtTokenValidatorException {
        var acceptedAudiences = Collections.singletonList("aud1");
        var validator = tokenValidator(acceptedAudiences);
        var now = new Date();
        var afterNow = new Date(now.getTime() + maxClockSkewMillis());
        var token = token(defaultClaims()
            .audience(acceptedAudiences)
            .notBeforeTime(afterNow)
            .build());
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token));
    }

    private JwtTokenValidator tokenValidator(List<String> acceptedAudiences) {
        return new DefaultConfigurableJwtValidator(DEFAULT_ISSUER, acceptedAudiences, jwkSource);
    }

    private JwtTokenValidator tokenValidator(List<String> acceptedAudiences, List<String> optionalClaims) {
        return new DefaultConfigurableJwtValidator(DEFAULT_ISSUER, acceptedAudiences, optionalClaims, jwkSource);
    }

    private long maxClockSkewMillis() {
        return TimeUnit.SECONDS.toMillis(DefaultJwtClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS + 5);
    }
}

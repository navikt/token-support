package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jwt.JWT;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
 class DefaultJwtTokenValidatorTest extends AbstractJwtValidatorTest {

    private static final String ISSUER = "https://issuer";
    private static final String SUB = "foobar";

    @Test
     void testAssertValidToken() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createOIDCTokenValidator(ISSUER, Collections.singletonList("aud1"));
        JWT token = createSignedJWT(ISSUER, "aud1", SUB);
        validator.assertValidToken(token.serialize());
    }

    @Test
     void testAssertUnexpectedIssuer() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createOIDCTokenValidator("https://differentfromtoken",
            Collections.singletonList("aud1"));
        JWT token = createSignedJWT(ISSUER, "aud1", SUB);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token.serialize()));
    }

    @Test
     void testAssertUnknownAudience() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createOIDCTokenValidator(ISSUER, Collections.singletonList("aud1"));
        JWT token = createSignedJWT(ISSUER, "unknown", SUB);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token.serialize()));
    }

    @Test
     void testGetValidator() throws ParseException, JwtTokenValidatorException {
        List<String> aud = new ArrayList<>();
        aud.add("aud1");
        aud.add("aud2");
        DefaultJwtTokenValidator validator = createOIDCTokenValidator(ISSUER, aud);

        JWT tokenAud1 = createSignedJWT(ISSUER, "aud1", SUB);
        assertEquals("aud1", validator.get(tokenAud1).getClientID().getValue());

        JWT tokenAud2 = createSignedJWT(ISSUER, "aud2", SUB);
        assertEquals("aud2", validator.get(tokenAud2).getClientID().getValue());

        JWT tokenUnknownAud = createSignedJWT(ISSUER, "unknown", SUB);

        assertThrows(JwtTokenValidatorException.class, () -> validator.get(tokenUnknownAud));
    }

    private DefaultJwtTokenValidator createOIDCTokenValidator(String issuer, List<String> expectedAudience) {
        try {
            return new DefaultJwtTokenValidator(
                issuer,
                expectedAudience,
                new RemoteJWKSet<>(URI.create("https://someurl").toURL(), new MockResourceRetriever())
            );
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
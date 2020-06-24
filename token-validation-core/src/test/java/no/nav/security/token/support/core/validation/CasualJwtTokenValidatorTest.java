package no.nav.security.token.support.core.validation;

import com.nimbusds.jwt.JWT;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class CasualJwtTokenValidatorTest extends AbstractJwtValidatorTest {

    private static final String ISSUER = "https://issuer";

    @Test
    public void assertValidToken() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createLaxTokenValidator(ISSUER);
        JWT token = createSignedJWT(ISSUER, null, null);
        validator.assertValidToken(token.serialize());
    }

    @Test
    public void testAssertUnexpectedIssuer() throws JwtTokenValidatorException {
        String otherIssuer = "https://differentfromtoken";
        JwtTokenValidator validator = createLaxTokenValidator(otherIssuer);
        JWT token = createSignedJWT(ISSUER, null, null);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token.serialize()));
    }

    private CasualJwtTokenValidator createLaxTokenValidator(String issuer) {
        try {
            return new CasualJwtTokenValidator(issuer, URI.create("https://someurl").toURL(), new MockResourceRetriever());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}

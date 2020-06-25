package no.nav.security.token.support.core.validation;

import com.nimbusds.jwt.JWT;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class ConfigurableJwtTokenValidatorTest extends AbstractJwtValidatorTest {

    private static final String ISSUER = "https://issuer";

    @Test
    public void assertValidToken() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createConfigurableTokenValidator(ISSUER, List.of("scope"));
        JWT token = createSignedJWT(ISSUER, List.of("scope"), null, null);
        validator.assertValidToken(token.serialize());
    }

    @Test
    public void testAssertUnexpectedIssuer() throws JwtTokenValidatorException {
        String otherIssuer = "https://differentfromtoken";
        JwtTokenValidator validator = createConfigurableTokenValidator(otherIssuer, List.of("scope"));
        JWT token = createSignedJWT(ISSUER, List.of("scope"), null, null);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token.serialize()));
    }

    @Test
    public void testAssertNoneExistingRequiredClaim() throws JwtTokenValidatorException {
        JwtTokenValidator validator = createConfigurableTokenValidator(ISSUER, List.of("scope"));
        JWT token = createSignedJWT(ISSUER, List.of("someotherclaim"), null, null);
        assertThrows(JwtTokenValidatorException.class, () -> validator.assertValidToken(token.serialize()));
    }

    private ConfigurableJwtTokenValidator createConfigurableTokenValidator(String issuer, List<String> requiredClaims) {
        try {
            return new ConfigurableJwtTokenValidator(issuer, URI.create("https://someurl").toURL(), requiredClaims, new MockResourceRetriever());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}

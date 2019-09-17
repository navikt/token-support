package no.nav.security.token.support.core.context;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenValidationContextTest {

    @Test
    public void getFirstValidToken() {

        Map<String, JwtToken> map = new ConcurrentHashMap<>();
        TokenValidationContext tokenValidationContext = new TokenValidationContext(map);

        assertThat(tokenValidationContext.getFirstValidToken()).isEmpty();
        assertThat(tokenValidationContext.hasValidToken()).isFalse();

        JwtToken jwtToken1 = jwtToken("https://one");
        JwtToken jwtToken2 = jwtToken("https://two");
        map.put("issuer2", jwtToken2);
        map.put("issuer1", jwtToken1);

        assertThat(tokenValidationContext.getFirstValidToken()).hasValueSatisfying(jwtToken -> jwtToken.getIssuer().equals(jwtToken2.getIssuer()));
    }

    private JwtToken jwtToken(String issuer) {
        PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("subject")
            .build());
        return new JwtToken(plainJWT.serialize());
    }
}

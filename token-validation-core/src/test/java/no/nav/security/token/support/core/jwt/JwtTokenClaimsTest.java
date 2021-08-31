package no.nav.security.token.support.core.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenClaimsTest {

    @Test
    void containsClaimShouldHandleBothStringAndListClaim() {
        assertThat(
            withClaim("arrayClaim", List.of("1","2")).containsClaim("arrayClaim", "1")
        ).isTrue();
        assertThat(
            withClaim("stringClaim", "1").containsClaim("stringClaim", "1")
        ).isTrue();
    }

    private JwtTokenClaims withClaim(String name, Object value) {
        var claims = new JWTClaimsSet.Builder().claim(name, value).build();
        //do json parsing to simulate usage when creating from token
        var tokenString = new PlainJWT(claims).serialize();
        try {
            return new JwtTokenClaims(PlainJWT.parse(tokenString).getJWTClaimsSet());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }
}

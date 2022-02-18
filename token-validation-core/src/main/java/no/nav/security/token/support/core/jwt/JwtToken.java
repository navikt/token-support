package no.nav.security.token.support.core.jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import java.text.ParseException;

public class JwtToken {

    private final String encodedToken;
    private final JWT jwt;
    private final JwtTokenClaims jwtTokenClaims;

    public JwtToken(String encodedToken) {
        try {
            this.encodedToken = encodedToken;
            this.jwt = JWTParser.parse(encodedToken);
            this.jwtTokenClaims = new JwtTokenClaims(getJwtClaimsSet());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public String getIssuer() {
        return jwtTokenClaims.getIssuer();
    }

    public String getSubject() {
        return jwtTokenClaims.getSubject();
    }

    public String getTokenAsString() {
        return encodedToken;
    }

    public boolean containsClaim(String name, String value) {
        return jwtTokenClaims.containsClaim(name, value);
    }

    public JwtTokenClaims getJwtTokenClaims() {
        return jwtTokenClaims;
    }

    protected JWT getJwt() {
        return jwt;
    }

    private JWTClaimsSet getJwtClaimsSet() throws ParseException {
        return jwt.getJWTClaimsSet();
    }
}

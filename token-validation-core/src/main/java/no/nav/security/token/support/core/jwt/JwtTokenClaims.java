package no.nav.security.token.support.core.jwt;

import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtTokenClaims {

    private final JWTClaimsSet jwtClaimsSet;

    public JwtTokenClaims(JWTClaimsSet jwtClaimsSet) {
        this.jwtClaimsSet = jwtClaimsSet;
    }

    public Object get(String name) {
        return getClaimSet().getClaim(name);
    }

    public String getStringClaim(String name) {
        try {
            return getClaimSet().getStringClaim(name);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public String getIssuer() {
        return getClaimSet().getIssuer();
    }

    public Date getExpirationTime() {
        return getClaimSet().getExpirationTime();
    }

    public String getSubject() {
        return getClaimSet().getSubject();
    }

    public List<String> getAsList(String name) {
        try {
            return getClaimSet().getStringListClaim(name);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean containsClaim(String name, String value) {
        Object claim = getClaimSet().getClaim(name);
        if (claim == null) {
            return false;
        }
        if (claim instanceof String) {
            String claimAsString = (String) claim;
            return claimAsString.equals(value) || value.equals("*");
        }
        if (claim instanceof Collection<?>) {
            Collection<?> claimasList = (Collection<?>) claim;
            return claimasList.contains(value) || (value.equals("*") && !claimasList.isEmpty());
        }
        return false;
    }

    public Map<String, Object> getAllClaims() {
        return getClaimSet().getClaims();
    }

    JWTClaimsSet getClaimSet() {
        return this.jwtClaimsSet;
    }
}

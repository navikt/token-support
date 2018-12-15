package no.nav.security.oidc.context;

import java.text.ParseException;
import java.util.List;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONArray;

public class OIDCClaims {

    private final JWT claims;

    public OIDCClaims(JWT jwt) {
        this.claims = jwt;
    }

    public String get(String name) {
        try {
            return getClaimSet().getStringClaim(name);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public JWTClaimsSet getClaimSet() {
        try {
            return this.claims.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
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
            return claimAsString.equals(value);
        }
        if (claim instanceof JSONArray) {
            JSONArray claimasList = (JSONArray) claim;
            return claimasList.contains(value);
        }
        return false;
    }
}

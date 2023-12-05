package no.nav.security.token.support.core.context;

import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.core.jwt.JwtTokenClaims;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class TokenValidationContext {

    private final Map<String, JwtToken> issuerShortNameValidatedTokenMap;

    public TokenValidationContext(Map<String, JwtToken> issuerShortNameValidatedTokenMap) {
        this.issuerShortNameValidatedTokenMap = issuerShortNameValidatedTokenMap;
    }

    public Optional<JwtToken> getJwtTokenAsOptional(String issuerName) {
        return jwtToken(issuerName);
    }

    public Optional<JwtToken> getFirstValidToken() {
        return issuerShortNameValidatedTokenMap.values().stream().findFirst();
    }

    public
    JwtToken getJwtToken(String issuerName) {
        return jwtToken(issuerName).orElse(null);
    }

    @Override
    public String toString() {
        return "TokenValidationContext{" +
            "issuers=" + issuerShortNameValidatedTokenMap.keySet() +
            '}';
    }

    public
    JwtTokenClaims getClaims(String issuerName) {
        return jwtToken(issuerName)
            .map(JwtToken::getJwtTokenClaims)
            .orElse(null);
    }

    public Optional<JwtTokenClaims> getAnyValidClaims() {
        return issuerShortNameValidatedTokenMap.values().stream()
            .map(JwtToken::getJwtTokenClaims)
            .findFirst();
    }

    public boolean hasValidToken() {
        return !issuerShortNameValidatedTokenMap.isEmpty();
    }

    public boolean hasTokenFor(String issuerName) {
        return jwtToken(issuerName).isPresent();
    }

    public List<String> getIssuers() {
        return new ArrayList<>(issuerShortNameValidatedTokenMap.keySet());
    }

    private Optional<JwtToken> jwtToken(String issuerName) {
        return issuerShortNameValidatedTokenMap.containsKey(issuerName) ?
            Optional.of(issuerShortNameValidatedTokenMap.get(issuerName))
            : Optional.empty();
    }
}
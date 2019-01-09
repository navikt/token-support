package no.nav.security.oidc.context;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class OIDCValidationContext {

    private final Map<String, TokenContext> validatedTokens;
    private final Map<String, OIDCClaims> validatedClaims;
    private final List<String> issuers;

    public OIDCValidationContext() {
        this.validatedTokens = new ConcurrentHashMap<>();
        this.validatedClaims = new ConcurrentHashMap<>();
        this.issuers = new ArrayList<>();
    }

    public void addValidatedToken(String issuer, TokenContext tokenContext, OIDCClaims claims) {
        validatedTokens.put(issuer, tokenContext);
        validatedClaims.put(issuer, claims);
        issuers.add(issuer);
    }

    public boolean hasValidTokenFor(String issuerName) {
        return validatedTokens.containsKey(issuerName);
    }

    public boolean hasTokenFor(String issuerName) {
        return validatedTokens.containsKey(issuerName);
    }

    public TokenContext getToken(String issuerName) {
        return validatedTokens.get(issuerName);
    }

    public OIDCClaims getClaims(String issuerName) {
        return validatedClaims.get(issuerName);
    }

    public Map<String, OIDCClaims> getClaims(){
        return validatedClaims;
    }

    public boolean hasValidToken() {
        return !validatedTokens.isEmpty();
    }

    public List<String> getIssuers() {
        return issuers;
    }

    public Optional<TokenContext> getFirstValidToken() {
        Optional<String> issuer = getIssuers().stream().findFirst();
        return issuer.isPresent()
                ? Optional.of(getToken(issuer.get()))
                : Optional.empty();
    }

}

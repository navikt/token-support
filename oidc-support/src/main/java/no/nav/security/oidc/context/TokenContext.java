package no.nav.security.oidc.context;

public class TokenContext {

    private final String idToken;
    private final String issuer;

    public TokenContext(String issuer, String idToken) {
        this.issuer = issuer;
        this.idToken = idToken;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getIdToken() {
        return idToken;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [issuer=" + issuer + ",idToken=" + idToken + "]";
    }

}

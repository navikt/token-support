package no.nav.security.oidc.context;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import jdk.nashorn.internal.parser.Token;
import org.junit.Test;

import static org.junit.Assert.*;

public class OIDCValidationContextTest {

    @Test
    public void getFirstValidToken() {
        OIDCValidationContext oidcValidationContext = new OIDCValidationContext();
        addValidatedToken("issuer2", oidcValidationContext);
        addValidatedToken("issuer1", oidcValidationContext);

        System.out.println(oidcValidationContext.getFirstValidToken());
    }
    private OIDCValidationContext addValidatedToken(String issuer, OIDCValidationContext oidcValidationContext){
        oidcValidationContext.addValidatedToken(issuer, new TokenContext(issuer,
                "tokenstring"), new OIDCClaims(new PlainJWT(new JWTClaimsSet.Builder().build())));
        return oidcValidationContext;
    }
}
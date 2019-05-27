package no.nav.security.spring.oidc.integrationtest;

import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.api.Unprotected;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Protected
@RestController
public class ProtectedRestController {

    static final String UNPROTECTED = "/unprotected";
    static final String PROTECTED = "/protected";
    static final String PROTECTED_WITH_CLAIMS = "/protected/withclaims";

    @GetMapping(PROTECTED)
    public String protectedMethod() {
        return "protected";
    }

    @ProtectedWithClaims(issuer = "knownissuer", claimMap = "importantclaim=vip, acr=Level4")
    @GetMapping(PROTECTED_WITH_CLAIMS)
    public String protectedWithClaimsMethod(){
        return "protected with some required claims";
    }

    @Unprotected
    @GetMapping(UNPROTECTED)
    public String unprotectedMethod() {
        return "unprotected";
    }

}

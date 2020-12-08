package no.nav.security.token.support.spring.integrationtest;

import org.springframework.web.bind.annotation.GetMapping;

@MetaProtected(MetaProtectedRestController.METAPROTECTED)
public class MetaProtectedRestController {
    static final String METAPROTECTED = "/metaprotected";

    @GetMapping
    public String metaProtectedWithClaimsMethod() {
        return "protected with some required claims";
    }

}

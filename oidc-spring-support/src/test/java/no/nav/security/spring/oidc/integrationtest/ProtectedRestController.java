package no.nav.security.spring.oidc.integrationtest;

import no.nav.security.oidc.api.Protected;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Protected
@RestController("/protected")
public class ProtectedRestController {

    @GetMapping
    public String protectedMethod() {
        return "protected";
    }
}

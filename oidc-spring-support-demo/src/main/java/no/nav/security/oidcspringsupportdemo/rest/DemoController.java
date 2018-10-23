package no.nav.security.oidcspringsupportdemo.rest;

import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.Unprotected;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Protected
@RestController
public class DemoController {

    @GetMapping("/demo/protected")
    public String protectedPath(){
        return "i am protected";
    }

    @Unprotected
    @GetMapping("/demo/unprotected")
    public String unprotectedPath(){
        return "i am unprotected";
    }
}

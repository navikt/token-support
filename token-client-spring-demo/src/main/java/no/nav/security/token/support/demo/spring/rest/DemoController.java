package no.nav.security.token.support.demo.spring.rest;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.demo.spring.client.DemoClient1;
import no.nav.security.token.support.demo.spring.client.DemoClient2;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Protected
@RestController
public class DemoController {

    private final DemoClient1 demoClient1;
    private final DemoClient2 demoClient2;

    public DemoController(DemoClient1 demoClient1, DemoClient2 demoClient2) {
        this.demoClient1 = demoClient1;
        this.demoClient2 = demoClient2;
    }

    @GetMapping("/protected")
    public String protectedPath(){
        return "i am protected";
    }

    @Unprotected
    @GetMapping("/unprotected")
    public String unprotectedPath(){
        return "i am unprotected";
    }

    @Unprotected
    @GetMapping("/unprotected/client_credentials")
    public String pingWithClientCredentials(){
        return demoClient1.ping();
    }

    @GetMapping("/protected/on_behalf_of")
    public String pingWithOnBehalfOf(){
        return demoClient2.ping();
    }
}

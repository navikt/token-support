package no.nav.security.token.support.demo.spring.rest;

import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.demo.spring.client.ClientCredentialsExampleClient;
import no.nav.security.token.support.demo.spring.client.OnBehalfOfExampleClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Protected
@RestController
public class DemoController {

    private final OnBehalfOfExampleClient onBehalfOfExampleClient;
    private final ClientCredentialsExampleClient clientCredentialsExampleClient;

    public DemoController(OnBehalfOfExampleClient onBehalfOfExampleClient,
                          ClientCredentialsExampleClient clientCredentialsExampleClient) {
        this.onBehalfOfExampleClient = onBehalfOfExampleClient;
        this.clientCredentialsExampleClient = clientCredentialsExampleClient;
    }

    @GetMapping("/protected")
    public String protectedPath(){
        return "i am protected";
    }

    @GetMapping("/protected/on_behalf_of")
    public String pingWithOnBehalfOf(){
        return onBehalfOfExampleClient.ping();
    }

    @Unprotected
    @GetMapping("/unprotected")
    public String unprotectedPath(){
        return "i am unprotected";
    }

    @Unprotected
    @GetMapping("/unprotected/client_credentials")
    public String pingWithClientCredentials(){
        return clientCredentialsExampleClient.ping();
    }
}

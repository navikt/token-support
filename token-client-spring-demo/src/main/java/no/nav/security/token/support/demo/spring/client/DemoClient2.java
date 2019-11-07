package no.nav.security.token.support.demo.spring.client;

import no.nav.security.token.support.demo.spring.config.DemoConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class DemoClient2 {

    private final String url;
    private final RestTemplate restTemplate;

    public DemoClient2(@Value("${democlient2.url}") String url,
                       @DemoConfiguration.DemoClient2 RestTemplate restTemplate) {
        this.url = url;
        this.restTemplate = restTemplate;
    }


    public String ping() {
        return restTemplate.getForObject(url + "/ping", String.class);
    }
}

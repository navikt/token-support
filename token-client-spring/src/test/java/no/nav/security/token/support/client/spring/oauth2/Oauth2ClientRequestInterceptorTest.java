package no.nav.security.token.support.client.spring.oauth2;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.web.client.MockRestServiceServer;

import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient;

@SpringBootTest(classes = { OAuth2AccessTokenService.class, OnBehalfOfTokenClient.class,
        DefaultOAuth2HttpClient.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
class Oauth2ClientRequestInterceptorTest {

    @MockBean
    JwtBearerTokenResolver resolver;
    private MockRestServiceServer mockServer;
    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        mockServer = MockRestServiceServer
                .bindTo(restTemplate.getRestTemplate())
                .ignoreExpectOrder(true)
                .bufferContent()
                .build();
    }

    @Test
    void testTemplate() {
        System.out.println(restTemplate);
    }

}

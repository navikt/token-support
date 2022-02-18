package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.ClientAuthenticationProperties;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.support.TestPropertySourceUtils;

import java.io.IOException;

import static no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {OAuth2ClientConfiguration.class, RestTemplateAutoConfiguration.class})
@ContextConfiguration(initializers = ClientConfigurationPropertiesTestWithWellKnownUrl.RandomPortInitializer.class)
@ActiveProfiles("test-withwellknownurl")
class ClientConfigurationPropertiesTestWithWellKnownUrl {

    @Autowired
    private MockWebServer mockWebServer;

    @MockBean
    private TokenValidationContextHolder tokenValidationContextHolder;

    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;

    @Test
    void testClientConfigIsValid() {
        assertThat(clientConfigurationProperties).isNotNull();
        assertThat(clientConfigurationProperties.getRegistration()).isNotNull();
        ClientProperties clientProperties =
            clientConfigurationProperties.getRegistration().values().stream().findFirst().orElse(null);
        assertThat(clientProperties).isNotNull();
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getClientAuthMethod()).isNotNull();
        assertThat(auth.getClientId()).isNotNull();
        assertThat(auth.getClientRsaKey()).isNotNull();
        assertThat(clientProperties.getTokenEndpointUrl()).isNotNull();
        assertThat(clientProperties.getGrantType().getValue()).isNotNull();
    }

    public static class RandomPortInitializer
        implements ApplicationContextInitializer<ConfigurableApplicationContext> {

        private final String wellKnown = "{\n" +
            "  \"issuer\" : \"https://someissuer\",\n" +
            "  \"token_endpoint\" : \"https://someissuer/token\",\n" +
            "  \"jwks_uri\" : \"https://someissuer/jwks\",\n" +
            "  \"grant_types_supported\" : [ \"urn:ietf:params:oauth:grant-type:token-exchange\" ],\n" +
            "  \"token_endpoint_auth_methods_supported\" : [ \"private_key_jwt\" ],\n" +
            "  \"token_endpoint_auth_signing_alg_values_supported\" : [ \"RS256\" ],\n" +
            "  \"subject_types_supported\" : [ \"public\" ]\n" +
            "}";


        @Override
        public void initialize(ConfigurableApplicationContext applicationContext) {
            GenericApplicationContext ctx = (GenericApplicationContext) applicationContext;
            MockWebServer server = new MockWebServer();
            ctx.registerBean("mockWebServer", MockWebServer.class, () -> server);
            try {
                server.start();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(applicationContext,
                "mockwebserver.port=" + server.getPort());
            server.enqueue(jsonResponse(wellKnown));
        }
    }
}

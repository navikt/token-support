package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.ClientAuthenticationProperties;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.*;

@SpringBootTest(classes = {OAuth2ClientConfiguration.class, ConfigurationWithCacheEnabled.class})
@ActiveProfiles("test-withresourceurl")
class ClientConfigurationPropertiesTestWithResourceUrl {

    @MockBean
    private TokenValidationContextHolder tokenValidationContextHolder;

    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;

    @BeforeEach
    void before() {
        MockitoAnnotations.initMocks(this);
    }

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
        assertThat(auth.getClientSecret()).isNotNull();
        assertThat(clientProperties.getScope()).isNotEmpty();
        assertThat(clientProperties.getTokenEndpointUrl()).isNotNull();
        assertThat(clientProperties.getGrantType().getValue()).isNotNull();
        assertThat(clientProperties.getResourceUrl()).isNotNull();
    }
}

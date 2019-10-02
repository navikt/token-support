package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {ClientConfigurationProperties.class})
@ActiveProfiles("test")
class ClientConfigurationPropertiesTest {

    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;

    @Test
    void testClientConfigIsValid() {
        assertThat(clientConfigurationProperties).isNotNull();
        assertThat(clientConfigurationProperties.getClients()).isNotNull();
        ClientConfigurationProperties.ClientProperties clientProperties = clientConfigurationProperties.getClients().values().stream().findFirst().orElse(null);
        assertThat(clientProperties).isNotNull();
        assertThat(clientProperties.getGrantType().getValue()).isNotNull();
    }
}

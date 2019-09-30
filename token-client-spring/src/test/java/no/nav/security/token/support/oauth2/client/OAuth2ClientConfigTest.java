package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ClientConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {OAuth2ClientConfig.class})
@ActiveProfiles("test")
class OAuth2ClientConfigTest {

    @Autowired
    private OAuth2ClientConfig oAuth2ClientConfig;

    @Test
    void testClientConfigIsValid() {
        assertThat(oAuth2ClientConfig).isNotNull();
        assertThat(oAuth2ClientConfig.getClients()).isNotNull();
        OAuth2ClientConfig.OAuth2Client oAuth2Client = oAuth2ClientConfig.getClients().values().stream().findFirst().orElse(null);
        assertThat(oAuth2Client).isNotNull();
        assertThat(oAuth2Client.getGrantType().getValue()).isNotNull();
    }
}

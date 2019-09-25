package no.nav.security.token.support.oauth2.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {OAuth2ClientConfig.class})
@ActiveProfiles("test")
class OAuth2ClientPropertiesConfigTest {

    @Autowired
    private OAuth2ClientConfig oAuth2ClientConfig;

    @Test
    void testClientConfigIsValid() {
        assertThat(oAuth2ClientConfig).isNotNull();
        assertThat(oAuth2ClientConfig.getClient()).isNotNull();
        assertThat(oAuth2ClientConfig.getClient().values().stream().findFirst().orElse(null)).isNotNull();
    }
}

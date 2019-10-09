package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {ClientConfigurationProperties.class})
@ActiveProfiles("test")
class ClientConfigurationPropertiesTest {

    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;

    @Test
    void testClientConfigIsValid() {
        assertThat(clientConfigurationProperties).isNotNull();
        assertThat(clientConfigurationProperties.getRegistration()).isNotNull();
        ClientConfigurationProperties.ClientProperties clientProperties = clientConfigurationProperties.getRegistration().values().stream().findFirst().orElse(null);
        assertThat(clientProperties).isNotNull();
        assertThat(clientProperties.getClientId()).isNotNull();
        assertThat(clientProperties.getClientSecret()).isNotNull();
        assertThat(clientProperties.getScope()).isNotEmpty();
        assertThat(clientProperties.getTokenEndpointUrl()).isNotNull();
        assertThat(clientProperties.getGrantType().getValue()).isNotNull();
    }

    @Test
    void testDifferentClientPropsShouldNOTBeEqualAndShouldMakeSurroundingRequestsUnequalToo() {
        Map<String,ClientConfigurationProperties.ClientProperties> props = clientConfigurationProperties.getRegistration();

        assertThat(props.size()).isGreaterThan(1);
        ClientConfigurationProperties.ClientProperties p1 = props.get("example1-onbehalfof");
        ClientConfigurationProperties.ClientProperties p2 = props.get("example1-onbehalfof2");

        assertThat(p1.equals(p2)).isFalse();
        assertThat(p1.equals(p1)).isTrue();

        final String assertion = "123";
        OnBehalfOfGrantRequest r1 = new OnBehalfOfGrantRequest(p1, assertion);
        OnBehalfOfGrantRequest r2 = new OnBehalfOfGrantRequest(p2, assertion);

        assertThat(r1.equals(r2)).isFalse();
    }
}

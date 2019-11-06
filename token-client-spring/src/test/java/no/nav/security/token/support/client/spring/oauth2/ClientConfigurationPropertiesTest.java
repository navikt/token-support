package no.nav.security.token.support.client.spring.oauth2;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.ClientAuthenticationProperties;
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfGrantRequest;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {OAuth2ClientConfiguration.class, RestTemplateAutoConfiguration.class})
@ActiveProfiles("test")
class ClientConfigurationPropertiesTest {

    @MockBean
    private TokenValidationContextHolder tokenValidationContextHolder;

    @Autowired
    private ClientConfigurationProperties clientConfigurationProperties;

    @BeforeEach
    void before(){
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
    }

    @Test
    void testClientConfigWithClientAuthMethodAsPrivateKeyJwt() {
        assertThat(clientConfigurationProperties).isNotNull();
        assertThat(clientConfigurationProperties.getRegistration()).isNotNull();
        ClientProperties clientProperties =
            clientConfigurationProperties.getRegistration().get("example1-clientcredentials3");
        assertThat(clientProperties).isNotNull();
        ClientAuthenticationProperties auth = clientProperties.getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getClientAuthMethod()).isEqualTo(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        assertThat(auth.getClientId()).isNotNull();
        assertThat(auth.getClientRsaKey()).isNotNull();
        assertThat(clientProperties.getScope()).isNotEmpty();
        assertThat(clientProperties.getTokenEndpointUrl()).isNotNull();
        assertThat(clientProperties.getGrantType().getValue()).isNotNull();
    }

    @Test
    void testDifferentClientPropsShouldNOTBeEqualAndShouldMakeSurroundingRequestsUnequalToo() {
        Map<String, ClientProperties> props = clientConfigurationProperties.getRegistration();

        assertThat(props.size()).isGreaterThan(1);
        ClientProperties p1 = props.get("example1-onbehalfof");
        ClientProperties p2 = props.get("example1-onbehalfof2");

        assertThat(p1.equals(p2)).isFalse();
        assertThat(p1.equals(p1)).isTrue();

        final String assertion = "123";
        OnBehalfOfGrantRequest r1 = new OnBehalfOfGrantRequest(p1, assertion);
        OnBehalfOfGrantRequest r2 = new OnBehalfOfGrantRequest(p2, assertion);

        assertThat(r1.equals(r2)).isFalse();
    }
}

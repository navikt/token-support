package no.nav.security.token.support.client.spring.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsGrantRequest;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfGrantRequest;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest(classes = {ConfigurationWithCacheEnabledFalse.class})
@ActiveProfiles("test")
class OAuth2ClientConfigurationWithoutCacheTest {

    @MockBean
    private RestTemplateBuilder restTemplateBuilder;
    @MockBean
    private TokenValidationContextHolder tokenValidationContextHolder;
    @Autowired
    private OAuth2AccessTokenService oAuth2AccessTokenService;

    private Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfCache;
    private Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsCache;

    @BeforeEach
    void before() {
        onBehalfOfCache = oAuth2AccessTokenService.getOnBehalfOfGrantCache();
        clientCredentialsCache = oAuth2AccessTokenService.getClientCredentialsGrantCache();
    }

    @Test
    void oAuth2AccessTokenServiceCreatedWithoutCache() {
        assertThat(oAuth2AccessTokenService).isNotNull();
        assertThat(onBehalfOfCache).isNull();
        assertThat(clientCredentialsCache).isNull();
    }
}

@Configuration
@EnableOAuth2Client
class ConfigurationWithCacheEnabledFalse {

}

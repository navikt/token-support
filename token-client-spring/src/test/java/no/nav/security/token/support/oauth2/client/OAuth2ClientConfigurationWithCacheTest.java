package no.nav.security.token.support.oauth2.client;

import com.github.benmanes.caffeine.cache.Cache;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.oauth2.EnableOAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest(classes = {ConfigurationWithCacheEnabledTrue.class})
@ActiveProfiles("test")
class OAuth2ClientConfigurationWithCacheTest {

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
    void oAuth2AccessTokenServiceCreatedWithCache() {
        assertThat(oAuth2AccessTokenService).isNotNull();
        assertThat(onBehalfOfCache).isNotNull();
        assertThat(clientCredentialsCache).isNotNull();
    }
}

@Configuration
@EnableOAuth2Client(cacheEnabled = true, cacheEvictSkew = 5, cacheMaximumSize = 100)
class ConfigurationWithCacheEnabledTrue {

}

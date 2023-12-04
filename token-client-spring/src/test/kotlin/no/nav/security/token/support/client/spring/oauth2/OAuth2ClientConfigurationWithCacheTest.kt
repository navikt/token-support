package no.nav.security.token.support.client.spring.oauth2

import com.github.benmanes.caffeine.cache.Cache
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsGrantRequest
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfGrantRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.test.context.ActiveProfiles
import no.nav.security.token.support.core.context.TokenValidationContextHolder

@SpringBootTest(classes = [ConfigurationWithCacheEnabledTrue::class])
@ActiveProfiles("test")
internal class OAuth2ClientConfigurationWithCacheTest {

    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var oAuth2AccessTokenService: OAuth2AccessTokenService
    private lateinit var onBehalfOfCache: Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse>
    private lateinit var clientCredentialsCache: Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse>
    @BeforeEach
    fun before() {
        onBehalfOfCache = oAuth2AccessTokenService.onBehalfOfGrantCache!!
        clientCredentialsCache = oAuth2AccessTokenService.clientCredentialsGrantCache!!
    }

    @Test
    fun oAuth2AccessTokenServiceCreatedWithCache() {
        assertThat(oAuth2AccessTokenService).isNotNull
        assertThat(onBehalfOfCache).isNotNull
        assertThat(clientCredentialsCache).isNotNull
    }
}

@Configuration
@EnableOAuth2Client(cacheEnabled = true, cacheEvictSkew = 5, cacheMaximumSize = 100)
internal class ConfigurationWithCacheEnabledTrue {
    @Bean
    @ConditionalOnMissingBean(RestTemplateBuilder::class)
    fun restTemplateBuilder(): RestTemplateBuilder {
        return RestTemplateBuilder()
    }
}
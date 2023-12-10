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

@SpringBootTest(classes = [ConfigurationWithCacheEnabledFalse::class])
@ActiveProfiles("test")
internal class OAuth2ClientConfigurationWithoutCacheTest {
    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var oAuth2AccessTokenService: OAuth2AccessTokenService

    @Test
    fun oAuth2AccessTokenServiceCreatedWithoutCache() {
        assertThat(oAuth2AccessTokenService).isNotNull
        assertThat(oAuth2AccessTokenService.clientCredentialsGrantCache).isNull()
        assertThat(oAuth2AccessTokenService.onBehalfOfGrantCache).isNull()
        assertThat(oAuth2AccessTokenService.exchangeGrantCache).isNull()
    }
}

@Configuration
@EnableOAuth2Client
internal class ConfigurationWithCacheEnabledFalse {
    @Bean
    @ConditionalOnMissingBean(RestTemplateBuilder::class)
    fun restTemplateBuilder()= RestTemplateBuilder()
}
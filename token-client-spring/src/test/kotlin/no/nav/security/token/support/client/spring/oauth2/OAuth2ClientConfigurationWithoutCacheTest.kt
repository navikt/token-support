package no.nav.security.token.support.client.spring.oauth2

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Configuration
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.bean.override.mockito.MockitoBean

@SpringBootTest(classes = [ConfigurationWithCacheEnabledFalse::class, RestClientAutoConfiguration::class])
@ActiveProfiles("test")
internal class OAuth2ClientConfigurationWithoutCacheTest {
    @MockitoBean
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
internal class ConfigurationWithCacheEnabledFalse
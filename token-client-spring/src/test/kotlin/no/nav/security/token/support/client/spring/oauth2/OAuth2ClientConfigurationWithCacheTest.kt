package no.nav.security.token.support.client.spring.oauth2

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.Configuration
import org.springframework.test.context.ActiveProfiles
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.core.context.TokenValidationContextHolder

@SpringBootTest(classes = [ConfigurationWithCacheEnabledTrue::class])
@ActiveProfiles("test")
internal class OAuth2ClientConfigurationWithCacheTest {

    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var oAuth2AccessTokenService: OAuth2AccessTokenService

    @Test
    fun oAuth2AccessTokenServiceCreatedWithCache() {
        assertThat(oAuth2AccessTokenService).isNotNull
        assertThat(oAuth2AccessTokenService.clientCredentialsGrantCache).isNotNull
        assertThat(oAuth2AccessTokenService.onBehalfOfGrantCache).isNotNull
        assertThat(oAuth2AccessTokenService.exchangeGrantCache).isNotNull
    }
}

@Configuration
@EnableOAuth2Client(cacheEnabled = true, cacheEvictSkew = 5, cacheMaximumSize = 100)
internal class ConfigurationWithCacheEnabledTrue
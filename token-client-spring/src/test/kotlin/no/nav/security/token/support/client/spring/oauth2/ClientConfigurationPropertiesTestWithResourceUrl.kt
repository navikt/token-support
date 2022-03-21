package no.nav.security.token.support.client.spring.oauth2


import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.MockitoAnnotations
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.test.context.ActiveProfiles
import java.net.URI

@SpringBootTest(classes = [OAuth2ClientConfiguration::class, RestTemplateAutoConfiguration::class])
@ActiveProfiles("test-withresourceurl")
internal class ClientConfigurationPropertiesTestWithResourceUrl {

    private  val matcher = object: ClientConfigurationPropertiesMatcher {

    }
    @MockBean
    private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var clientConfigurationProperties: ClientConfigurationProperties
    @BeforeEach
    fun before() {
        MockitoAnnotations.openMocks(this)
    }

    @Test
    fun testClientConfigIsValid() {
        assertThat(matcher.findProperties(clientConfigurationProperties, URI.create("https://isdialogmelding.dev.intern.nav.no/api/person/v1/behandler/self"))).isNotNull
        assertThat(clientConfigurationProperties).isNotNull
        assertThat(clientConfigurationProperties.registration).isNotNull
        val clientProperties = clientConfigurationProperties.registration.values.stream().findFirst().orElse(null)
        assertThat(clientProperties).isNotNull
        val auth = clientProperties.authentication
        assertThat(auth).isNotNull
        assertThat(auth.clientAuthMethod).isNotNull
        assertThat(auth.clientId).isNotNull
        assertThat(auth.clientSecret).isNotNull
        assertThat(clientProperties.scope).isNotEmpty
        assertThat(clientProperties.tokenEndpointUrl).isNotNull
        assertThat(clientProperties.grantType.value).isNotNull
        assertThat(clientProperties.resourceUrl).isNotNull
    }
}
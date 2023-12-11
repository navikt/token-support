package no.nav.security.token.support.client.spring.oauth2


import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.client.spring.oauth2.ClientConfigurationPropertiesTestWithWellKnownUrl.RandomPortInitializer
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.support.GenericApplicationContext
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.ContextConfiguration
import java.util.function.Supplier

import org.springframework.test.context.support.TestPropertySourceUtils.*
import no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse
import no.nav.security.token.support.core.context.TokenValidationContextHolder

@SpringBootTest(classes = [OAuth2ClientConfiguration::class, RestTemplateAutoConfiguration::class])
@ContextConfiguration(initializers = [RandomPortInitializer::class])
@ActiveProfiles("test-withwellknownurl")
internal class ClientConfigurationPropertiesTestWithWellKnownUrl {

   @MockBean
   private val tokenValidationContextHolder: TokenValidationContextHolder? = null

    @Autowired
    private lateinit var clientConfigurationProperties: ClientConfigurationProperties
    @Test
    fun testClientConfigIsValid() {
        assertThat(clientConfigurationProperties).isNotNull
        val clientProperties = clientConfigurationProperties.registration.values.firstOrNull()
        assertThat(clientProperties).isNotNull
        val auth = clientProperties?.authentication
        assertThat(auth?.clientId).isNotNull
        assertThat(auth?.clientRsaKey).isNotNull
        assertThat(clientProperties?.tokenEndpointUrl).isNotNull
        assertThat(clientProperties?.grantType?.value).isNotNull
    }

    class RandomPortInitializer : ApplicationContextInitializer<ConfigurableApplicationContext> {
        private val wellKnown = """{
                      "issuer" : "https://someissuer",
                      "token_endpoint" : "https://someissuer/token",
                      "jwks_uri" : "https://someissuer/jwks",
                      "grant_types_supported" : [ "urn:ietf:params:oauth:grant-type:token-exchange" ],
                      "token_endpoint_auth_methods_supported" : [ "private_key_jwt" ],
                      "token_endpoint_auth_signing_alg_values_supported" : [ "RS256" ],
                      "subject_types_supported" : [ "public" ]
                    }"""

        override fun initialize(applicationContext: ConfigurableApplicationContext) {
            val server = MockWebServer()
            (applicationContext as GenericApplicationContext).registerBean("mockWebServer", MockWebServer::class.java, Supplier { server })
            server.start()
            addInlinedPropertiesToEnvironment(applicationContext, "mockwebserver.port=" + server.port)
            server.enqueue(jsonResponse(wellKnown))
        }
    }
}
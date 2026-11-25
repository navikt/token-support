package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldNotBe
import java.util.function.Supplier
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.client.spring.oauth2.TestUtils.jsonResponse
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import okhttp3.mockwebserver.MockWebServer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.context.support.GenericApplicationContext
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.context.support.TestPropertySourceUtils.addInlinedPropertiesToEnvironment

@SpringBootTest(classes = [OAuth2ClientConfiguration::class, RestClientAutoConfiguration::class])
@ContextConfiguration(initializers = [ClientConfigurationPropertiesWithWellKnownUrlTest.RandomPortInitializer::class])
@ActiveProfiles("test-withwellknownurl")
internal class ClientConfigurationPropertiesWithWellKnownUrlTest : BehaviorSpec() {
    @MockitoBean
    private lateinit var tokenValidationContextHolder: TokenValidationContextHolder

    @Autowired
    private lateinit var clientConfigurationProperties: ClientConfigurationProperties

    init {
        extensions(SpringExtension())

        Given("en klientregistrering med en well-known-URL") {
            When("registreringen bindes og metadata hentes") {
                Then("skal fylle ut egenskapene for autentisering og tokenendepunkt") {
                    val properties = clientConfigurationProperties.registration["example1-token-exchange1"]
                        .shouldNotBeNull()
                    assertSoftly(properties) {
                        assertSoftly(authentication) {
                            clientId shouldNotBe null
                            clientRsaKey shouldNotBe null
                        }
                        tokenEndpointUrl shouldNotBe null
                        grantType.value shouldNotBe null
                    }
                }
            }
        }
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
            (applicationContext as GenericApplicationContext).registerBean(
                "mockWebServer", MockWebServer::class.java, Supplier { server }
            )
            server.start()
            addInlinedPropertiesToEnvironment(applicationContext, "mockwebserver.port=${server.port}")
            server.enqueue(jsonResponse(wellKnown))
        }
    }
}

package no.nav.security.token.support.client.spring.oauth2

import io.kotest.assertions.assertSoftly
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldNotBe
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.bean.override.mockito.MockitoBean

@SpringBootTest(classes = [OAuth2ClientConfiguration::class, RestClientAutoConfiguration::class])
@ActiveProfiles("test-withresourceurl")
internal class ClientConfigurationPropertiesWithResourceUrlTest : BehaviorSpec() {
    @MockitoBean
    private lateinit var tokenValidationContextHolder: TokenValidationContextHolder

    @Autowired
    private lateinit var clientConfigurationProperties: ClientConfigurationProperties

    init {
        extensions(SpringExtension())

        Given("en klientregistrering med en ressurs-URL") {
            When("en forespørsels-URL matches mot registreringen") {
                Then("skal finne registreringen og binde de påkrevde egenskapene") {
                    val matcher = object : ClientConfigurationPropertiesMatcher {}
                    val properties = matcher.findProperties(
                        clientConfigurationProperties,
                        "https://example1-onbehalfof.example/api/person/v1/behandler/self"
                    ).shouldNotBeNull()
                    assertSoftly(properties) {
                        assertSoftly(authentication) {
                            clientId shouldNotBe null
                            clientSecret shouldNotBe null
                        }
                        scope.shouldNotBeEmpty()
                        tokenEndpointUrl shouldNotBe null
                        grantType.value shouldNotBe null
                        resourceUrl shouldNotBe null
                    }
                }
            }
        }
    }
}

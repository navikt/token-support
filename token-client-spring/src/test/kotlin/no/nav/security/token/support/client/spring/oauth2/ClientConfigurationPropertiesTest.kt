package no.nav.security.token.support.client.spring.oauth2

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.test.context.ActiveProfiles
import org.springframework.web.client.RestClient
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfGrantRequest
import no.nav.security.token.support.client.spring.ClientConfigurationProperties
import no.nav.security.token.support.core.context.TokenValidationContextHolder

@SpringBootTest(classes = [OAuth2ClientConfiguration::class, RestClientAutoConfiguration::class])
@ActiveProfiles("test")
internal class ClientConfigurationPropertiesTest {

    @MockBean
    private lateinit var tokenValidationContextHolder: TokenValidationContextHolder

    @Autowired
    private lateinit var clientConfigurationProperties: ClientConfigurationProperties
    @Test
    fun testClientConfigIsValid() {
        val clientProperties = clientConfigurationProperties.registration.values.firstOrNull()
        assertThat(clientProperties).isNotNull
        val auth = clientProperties?.authentication
        assertThat(auth?.clientAuthMethod).isNotNull
        assertThat(auth?.clientId).isNotNull
        assertThat(auth?.clientSecret).isNotNull
        assertThat(clientProperties?.scope).isNotEmpty
        assertThat(clientProperties?.tokenEndpointUrl).isNotNull
        assertThat(clientProperties?.grantType?.value).isNotNull
    }

    @Test
    fun testTokenExchangeProperties() {
        assertThat(clientConfigurationProperties.registration).isNotNull
        val clientProperties = clientConfigurationProperties.registration["example1-token-exchange1"]
        assertThat(clientProperties).isNotNull
        assertThat(clientProperties!!.tokenExchange?.audience).isNotBlank
    }

    @Test
    fun testClientConfigWithClientAuthMethodAsPrivateKeyJwt() {
        assertThat(clientConfigurationProperties.registration).isNotNull
        val clientProperties = clientConfigurationProperties.registration["example1-clientcredentials3"]
        assertThat(clientProperties).isNotNull
        val auth = clientProperties?.authentication
        assertThat(auth)?.isNotNull
        assertThat(auth?.clientAuthMethod).isEqualTo(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        assertThat(auth?.clientId).isNotNull
        assertThat(auth?.clientRsaKey).isNotNull
        assertThat(clientProperties?.scope).isNotEmpty
        assertThat(clientProperties?.tokenEndpointUrl).isNotNull
        assertThat(clientProperties?.grantType?.value).isNotNull
    }

    @Test
    fun testDifferentClientPropsShouldNOTBeEqualAndShouldMakeSurroundingRequestsUnequalToo() {
        val props = clientConfigurationProperties.registration
        assertThat(props.size).isGreaterThan(1)
        val p1 = props.get("example1-onbehalfof")
        val p2 = props.get("example1-onbehalfof2")
        assertThat(p1 == p2).isFalse
        val assertion = "123"
        val r1 = OnBehalfOfGrantRequest(p1!!, assertion)
        val r2 = OnBehalfOfGrantRequest(p2!!, assertion)
        assertThat(r1 == r2).isFalse
    }
}
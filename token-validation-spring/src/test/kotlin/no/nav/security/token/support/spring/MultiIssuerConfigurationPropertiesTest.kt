package no.nav.security.token.support.spring

import com.nimbusds.jwt.JWTClaimNames.AUDIENCE
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit.jupiter.SpringExtension

@TestPropertySource(locations = ["/issuers.properties"])
@ExtendWith(SpringExtension::class)
@EnableConfigurationProperties(MultiIssuerProperties::class)
class MultiIssuerConfigurationPropertiesTest {

    @Autowired
    private lateinit var config: MultiIssuerProperties
    @Test
    fun test() {
        assertFalse(config.issuer.isEmpty())
        assertTrue(config.issuer.containsKey("number1"))
        assertEquals("http://metadata", "${config.issuer["number1"]?.discoveryUrl}")
        assertTrue(config.issuer["number1"]!!.acceptedAudience.contains("aud1"))
        assertTrue(config.issuer.containsKey("number2"))
        assertEquals("http://metadata2", "${config.issuer["number2"]?.discoveryUrl}")
        assertTrue(config.issuer["number2"]!!.acceptedAudience.contains("aud2"))
        assertTrue(config.issuer.containsKey("number3"))
        assertEquals("http://metadata3", "${config.issuer["number3"]?.discoveryUrl}")
        assertTrue(config.issuer["number3"]!!.acceptedAudience.contains("aud3") && config.issuer["number3"]!!.acceptedAudience.contains("aud4"))
        assertTrue(config.issuer.containsKey("number4"))
        assertEquals("http://metadata4", "${config.issuer["number4"]?.discoveryUrl}")
        assertThat(config.issuer["number4"]?.validation?.optionalClaims).containsExactly(SUBJECT, AUDIENCE)
        assertTrue(config.issuer.containsKey("number5"))
        assertEquals("http://metadata5", config.issuer["number5"]!!.discoveryUrl.toString())
        assertEquals(15L, config.issuer["number5"]?.jwksCache?.lifespan)
        assertEquals(5L, config.issuer["number5"]?.jwksCache?.refreshTime)
    }
}
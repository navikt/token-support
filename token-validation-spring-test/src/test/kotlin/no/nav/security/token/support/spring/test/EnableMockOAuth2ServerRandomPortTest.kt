package no.nav.security.token.support.spring.test


import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.NONE
import no.nav.security.mock.oauth2.MockOAuth2Server

@SpringBootTest(classes = [TestApplication::class], properties = ["discoveryUrl=http://localhost:\${mock-oauth2-server.port}/test/.well-known/openid-configuration"], webEnvironment = NONE)
@EnableMockOAuth2Server
internal class EnableMockOAuth2ServerRandomPortTest {

    @Autowired
    private lateinit var properties : MockOAuth2ServerProperties

    @Autowired
    private lateinit var server : MockOAuth2Server

    @Value("\${discoveryUrl}")
    private lateinit var  discoveryUrl : String

    @Test
    fun serverStartsOnRandomPortAndIsUpdatedInEnv() {
        assertEquals(server.baseUrl().port,properties.port)
        assertThat(server.wellKnownUrl("test")).hasToString(discoveryUrl)
    }
}
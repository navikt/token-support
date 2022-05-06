package no.nav.security.token.support.ktor

import io.kotest.assertions.asClue
import io.kotest.matchers.shouldBe
import io.ktor.server.config.MapApplicationConfig
import no.nav.security.mock.oauth2.withMockOAuth2Server
import no.nav.security.token.support.core.configuration.IssuerProperties
import org.junit.jupiter.api.Test

internal class TokenSupportAuthenticationProviderKtTest {

    @Test
    fun `config properties are parsed correctly`() {
        withMockOAuth2Server {
            val config = MapApplicationConfig(
                "no.nav.security.jwt.expirythreshold" to "5",
                "no.nav.security.jwt.issuers.size" to "1",
                "no.nav.security.jwt.issuers.0.issuer_name" to "da issuah",
                "no.nav.security.jwt.issuers.0.discoveryurl" to this.wellKnownUrl("whatever").toString(),
                "no.nav.security.jwt.issuers.0.accepted_audience" to "da audienze",
                "no.nav.security.jwt.issuers.0.jwks_cache.lifespan" to "20",
                "no.nav.security.jwt.issuers.0.jwks_cache.refreshtime" to "57",
                "no.nav.security.jwt.issuers.0.validation.optional_claims" to "sub"
            )

            config.asIssuerProps().asClue {
                it["da issuah"]?.acceptedAudience shouldBe listOf("da audienze")
                it["da issuah"]?.discoveryUrl shouldBe this.wellKnownUrl("whatever").toUrl()
                it["da issuah"]?.jwksCache shouldBe IssuerProperties.JwksCache(20, 57)
                it["da issuah"]?.validation shouldBe IssuerProperties.Validation(listOf("sub"))
            }
        }
    }


}
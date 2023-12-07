package no.nav.security.token.support.core.context

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import java.util.concurrent.ConcurrentHashMap
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.jwt.JwtToken

internal class TokenValidationContextTest {

    @Test
    fun firstValidToken() {
            val map : MutableMap<String, JwtToken> = ConcurrentHashMap()
            val tokenValidationContext = TokenValidationContext(map)
            assertThat(tokenValidationContext.firstValidToken).isEmpty()
            assertThat(tokenValidationContext.hasValidToken()).isFalse()

            val jwtToken1 = jwtToken("https://one")
            val jwtToken2 = jwtToken("https://two")
            map["issuer2"] = jwtToken2
            map["issuer1"] = jwtToken1

            assertThat(tokenValidationContext.firstValidToken).hasValueSatisfying { jwtToken -> jwtToken.issuer == jwtToken2.issuer }
        }

    private fun jwtToken(issuer : String) = JwtToken(PlainJWT(Builder().issuer(issuer).subject("subject").build()).serialize())
}
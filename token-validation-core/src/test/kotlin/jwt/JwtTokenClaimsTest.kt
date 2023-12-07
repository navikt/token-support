package jwt

import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import java.text.ParseException
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test
import no.nav.security.token.support.core.jwt.JwtTokenClaims

internal class JwtTokenClaimsTest {

    @Test
    fun containsClaimShouldHandleBothStringAndListClaim() {
        assertThat(withClaim("arrayClaim", listOf("1", "2")).containsClaim("arrayClaim", "1")).isTrue()
        assertThat(withClaim("stringClaim", "1").containsClaim("stringClaim", "1")).isTrue()
    }

    @Test
    fun containsClaimShouldHandleAsterisk() {
        assertThat(withClaim("stringClaim", "1").containsClaim("stringClaim", "*")).isTrue()
        assertThat(withClaim("emptyStringClaim", "").containsClaim("emptyStringClaim", "*")).isTrue()
        assertThat(withClaim("nullStringClaim", null).containsClaim("nullStringClaim", "*")).isFalse()
        assertThat(withClaim("arrayClaim", listOf("1", "2")).containsClaim("arrayClaim", "*")).isTrue()
        assertThat(withClaim("emptyArrayClaim", listOf<Any>()).containsClaim("emptyArrayClaim", "*")).isTrue()
    }
    private fun withClaim(name : String, value : Any?) = JwtTokenClaims(PlainJWT.parse(PlainJWT(Builder().claim(name, value).build()).serialize()).jwtClaimsSet)
}
package no.nav.security.token.support.filter

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.text.ParseException
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import no.nav.security.token.support.core.JwtTokenConstants
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.jwt.JwtTokenClaims
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito.anyString
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever

@ExtendWith(MockitoExtension::class)
internal class JwtTokenExpiryFilterTest {

    @Mock
    private val servletRequest : HttpServletRequest? = null

    @Mock
    private val filterChain : FilterChain? = null

    @Mock
    private val servletResponse : HttpServletResponse? = null
    private lateinit var tokenValidationContextHolder : TokenValidationContextHolder
    @Test
    fun tokenExpiresBeforeThreshold() {
        setupMocks(LocalDateTime.now().plusMinutes(2))

        val jwtTokenExpiryFilter = JwtTokenExpiryFilter(tokenValidationContextHolder, EXPIRY_THRESHOLD)
        jwtTokenExpiryFilter.doFilter(servletRequest!!, servletResponse!!, filterChain!!)
        verify(servletResponse).setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true")
    }

    @Test
    fun tokenExpiresAfterThreshold() {
        setupMocks(LocalDateTime.now().plusMinutes(3))

        val jwtTokenExpiryFilter = JwtTokenExpiryFilter(tokenValidationContextHolder, EXPIRY_THRESHOLD)
        jwtTokenExpiryFilter.doFilter(servletRequest!!, servletResponse!!, filterChain!!)
        verify(servletResponse, never()).setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true")
    }

    @Test
    fun noValidToken() {
        val jwtTokenExpiryFilter = JwtTokenExpiryFilter(mock(TokenValidationContextHolder::class.java),
            EXPIRY_THRESHOLD)
        jwtTokenExpiryFilter.doFilter(servletRequest!!, servletResponse!!, filterChain!!)
        verify(servletResponse, never()).setHeader(JwtTokenConstants.TOKEN_EXPIRES_SOON_HEADER, "true")
    }

    private fun setupMocks(expiry : LocalDateTime) {
        tokenValidationContextHolder = mock(TokenValidationContextHolder::class.java)
        val tokenValidationContext = mock(TokenValidationContext::class.java)
        whenever(tokenValidationContextHolder.getTokenValidationContext()).thenReturn(tokenValidationContext)
        whenever(tokenValidationContext.issuers).thenReturn(listOf("issuer1"))

        val expiryDate = Date.from(expiry.atZone(ZoneId.systemDefault()).toInstant())
        whenever(tokenValidationContext.getClaims(anyString())).thenReturn(createOIDCClaims(expiryDate))
    }

    companion object {

        private const val EXPIRY_THRESHOLD : Long = 1

        private fun createOIDCClaims(expiry : Date) =
            try {
                val jwt : JWT = PlainJWT(Builder()
                    .subject("subject")
                    .issuer("http//issuer1")
                    .expirationTime(expiry).build())
                JwtTokenClaims(jwt.jwtClaimsSet)
            }
            catch (e : ParseException) {
                throw RuntimeException(e)
            }
    }
}
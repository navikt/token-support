package no.nav.security.token.support.filter

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.IOUtils
import com.nimbusds.jose.util.Resource
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimNames.*
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.io.IOException
import java.io.InputStream
import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Arrays
import java.util.Date
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.junit.jupiter.MockitoExtension
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.context.TokenValidationContext
import no.nav.security.token.support.core.context.TokenValidationContextHolder
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler
import no.nav.security.token.support.filter.JwtTokenValidationFilter.Companion.fromHttpServletRequest

@ExtendWith(MockitoExtension::class)
internal class JwtTokenValidationFilterTest {

    @Mock
    private val servletRequest : HttpServletRequest? = null

    @Mock
    private val servletResponse : HttpServletResponse? = null

    @Test
    fun testSingleValidIdTokenInCookie() {
        val issuername = "myissuer"
        val issuerProps = createIssuerPropertiesMap(issuername, IDTOKENCOOKIENAME)
        val mockResources = MockResourceRetriever(issuername)
        val ctxHolder : TokenValidationContextHolder = TestTokenValidationContextHolder()

        val filter = createFilterToTest(issuerProps, mockResources, ctxHolder)
        val jwt = createJWT(issuername, mockResources.keysForIssuer(issuername)!!.toRSAPrivateKey())

        val filterCallCounter = intArrayOf(0)

        `when`(servletRequest!!.cookies).thenReturn(arrayOf(Cookie("JSESSIONID", "ABCDEF"), Cookie(IDTOKENCOOKIENAME, jwt)))
        filter.doFilter(servletRequest, servletResponse!!,
            mockFilterchainAsserting(issuername, "foobar", ctxHolder, filterCallCounter))

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once")
    }

    @Test
    fun testSingleValidIdTokenInHeader() {
        val anotherIssuer = "anotherIssuer"
        val issuerProps = createIssuerPropertiesMap(anotherIssuer, IDTOKENCOOKIENAME)

        val mockResources = MockResourceRetriever(anotherIssuer)
        val ctxHolder : TokenValidationContextHolder = TestTokenValidationContextHolder()
        val filter = createFilterToTest(issuerProps, mockResources, ctxHolder)

        val jwt = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer)!!.toRSAPrivateKey())

        val filterCallCounter = intArrayOf(0)

        `when`(servletRequest!!.cookies).thenReturn(null)
        `when`(servletRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer $jwt")
        filter.doFilter(servletRequest, servletResponse!!,
            mockFilterchainAsserting(anotherIssuer, "foobar", ctxHolder, filterCallCounter))

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once")
    }

    @Test
    fun testTwoValidIdTokensWithDifferentIssuersInHeader() {
        val issuer1 = "issuer1"
        val anotherIssuer = "issuerNumberTwo"
        val issuerProps : MutableMap<String, IssuerProperties> = HashMap()
        issuerProps.putAll(createIssuerPropertiesMap(issuer1, null))
        issuerProps.putAll(createIssuerPropertiesMap(anotherIssuer, null))

        val mockResources = MockResourceRetriever(issuer1, anotherIssuer)
        val ctxHolder : TokenValidationContextHolder = TestTokenValidationContextHolder()
        val filter = createFilterToTest(issuerProps, mockResources, ctxHolder)

        val jwt1 = createJWT(issuer1, mockResources.keysForIssuer(issuer1)!!.toRSAPrivateKey())
        val jwt2 = createJWT(anotherIssuer, mockResources.keysForIssuer(anotherIssuer)!!.toRSAPrivateKey())

        val filterCallCounter = intArrayOf(0)

        `when`(servletRequest!!.cookies).thenReturn(null)
        `when`(servletRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer $jwt1,Bearer $jwt2")
        filter.doFilter(servletRequest, servletResponse!!,
            mockFilterchainAsserting(arrayOf(issuer1, anotherIssuer), arrayOf("foobar", "foobar"), ctxHolder, filterCallCounter))

        assertEquals(1, filterCallCounter[0], "doFilter should have been called once")
    }

    @Test
    fun testRequestConverterShouldHandleWhenCookiesAreNULL() {
        `when`(servletRequest!!.cookies).thenReturn(null)
        `when`(servletRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null)

        val req = fromHttpServletRequest(servletRequest)
        assertNull(req.getCookies())
        assertNull(req.getHeader(AUTHORIZATION_HEADER))
    }

    @Test
    fun testRequestConverterShouldConvertCorrectly() {
        `when`(servletRequest!!.cookies).thenReturn(arrayOf(Cookie("JSESSIONID", "ABCDEF"), Cookie("IDTOKEN", "THETOKEN")))
        `when`(servletRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer eyAAA")

        val req = fromHttpServletRequest(servletRequest)
        req.getCookies()?.get(0)?.getName()
        assertEquals("JSESSIONID", req.getCookies()?.first()?.getName())
        assertEquals("ABCDEF", req.getCookies()?.first()?.getValue())
        assertEquals("IDTOKEN", req.getCookies()?.get(1)?.getName())
        assertEquals("THETOKEN", req.getCookies()?.get(1)?.getValue())
        assertEquals("Bearer eyAAA", req.getHeader(AUTHORIZATION_HEADER))
    }

    private fun mockFilterchainAsserting(issuer : String, subject : String, ctxHolder : TokenValidationContextHolder, filterCallCounter : IntArray) : FilterChain {
        return mockFilterchainAsserting(arrayOf(issuer), arrayOf(subject), ctxHolder, filterCallCounter)
    }

    private fun mockFilterchainAsserting(issuers : Array<String>, subjects : Array<String>, ctxHolder : TokenValidationContextHolder,
                                         filterCallCounter : IntArray) : FilterChain {
        return FilterChain { _, _ ->
            // TokenValidationContext is nulled after filter-call, so we check it here:
            filterCallCounter[0]++
            val ctx = ctxHolder.getTokenValidationContext()
            assertTrue(ctx.hasValidToken())
            assertEquals(issuers.size, ctx.issuers.size)
            for (i in issuers.indices) {
                assertTrue(ctx.hasTokenFor(issuers[i]))
                assertEquals(subjects[i], ctx.getClaims(issuers[i]).getStringClaim(SUBJECT))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    private fun createFilterToTest(issuerProps : Map<String, IssuerProperties>,
                                   mockResources : MockResourceRetriever, ctxHolder : TokenValidationContextHolder) : JwtTokenValidationFilter {
        val conf = MultiIssuerConfiguration(issuerProps, mockResources)
        val jwtTokenValidationHandler = JwtTokenValidationHandler(conf)
        return JwtTokenValidationFilter(jwtTokenValidationHandler, ctxHolder)
    }

    @Throws(URISyntaxException::class, MalformedURLException::class)
    private fun createIssuerPropertiesMap(issuer : String, cookieName : String?) : Map<String, IssuerProperties> {
        val issuerPropertiesMap : MutableMap<String, IssuerProperties> = HashMap()
        issuerPropertiesMap[issuer] = IssuerProperties(URI("https://$issuer").toURL(),
            listOf(AUDIENCE),
            cookieName)
        return issuerPropertiesMap
    }

    @Throws(JOSEException::class)
    private fun createJWT(issuer : String, signingKey : RSAPrivateKey) : String {
        val now = Date()
        val claimsSet = Builder()
            .subject("foobar").issuer(issuer).audience(AUDIENCE).notBeforeTime(now).issueTime(now)
            .expirationTime(Date(now.time + 3600)).build()

        val signer : JWSSigner = RSASSASigner(signingKey)
        val signedJWT = SignedJWT(
            JWSHeader(JWSAlgorithm.RS256, null, null, null, null, null, null, null, null, null, KEYID, null, null), claimsSet)
        signedJWT.sign(signer)
        return signedJWT.serialize()
    }

    private class TestTokenValidationContextHolder : TokenValidationContextHolder {

        var ctx  = TokenValidationContext(emptyMap())

        override fun getTokenValidationContext() = ctx

        override fun setTokenValidationContext(tokenValidationContext : TokenValidationContext?) {
            if (tokenValidationContext != null) {
                this.ctx = tokenValidationContext
            }
        }
    }

    internal class MockResourceRetriever(vararg mockedIssuers : String) : ProxyAwareResourceRetriever() {

        val mockedIssuers : Array<out String>
        val keys : MutableMap<String, RSAKey> = HashMap()

        init {
            this.mockedIssuers = mockedIssuers
            for (iss in mockedIssuers) {
                keys[iss] = genkey()
            }
        }

        fun keysForIssuer(issuer : String) : RSAKey? {
            return keys[issuer]
        }

        private fun genkey() : RSAKey {
            try {
                val gen = KeyPairGenerator.getInstance("RSA")
                gen.initialize(2048)
                val keyPair = gen.generateKeyPair()
                return RSAKey.Builder(keyPair.public as RSAPublicKey)
                    .privateKey(keyPair.private as RSAPrivateKey)
                    .keyID(KEYID).build()
            }
            catch (nsae : NoSuchAlgorithmException) {
                throw RuntimeException(nsae)
            }
        }

        @Throws(IOException::class)
        override fun retrieveResource(url : URL) : Resource {
            val jkwsPrefix = "http://jwks"
            if (url.toString().startsWith(jkwsPrefix)) {
                return retrieveJWKS(url.toString().substring(jkwsPrefix.length))
            }
            else if (Arrays.binarySearch(mockedIssuers, url.host) >= 0) {
                val issuer = url.host
                var content = contentFromFile
                content = content.replace("\$ISSUER", issuer)
                content = content.replace(jkwsPrefix, jkwsPrefix + issuer)
                return Resource(content, "application/json")
            }
            throw RuntimeException("dont know about issuer $url")
        }

        @get:Throws(IOException::class)
        private val contentFromFile : String
            get() = IOUtils.readInputStreamToString(getInputStream("/mockmetadata.json"), StandardCharsets.UTF_8)

        private fun getInputStream(file : String) : InputStream {
            return MockResourceRetriever::class.java.getResourceAsStream(file)
        }

        fun retrieveJWKS(issuer : String) : Resource {
            val set = JWKSet(keys[issuer])
            val content = set.toString()
            return Resource(content, "application/json")
        }
    }

    companion object {

        private const val KEYID = "myKeyId"
        private const val AUDIENCE = "aud1"
        private const val IDTOKENCOOKIENAME = "idtokencookie"
    }
}
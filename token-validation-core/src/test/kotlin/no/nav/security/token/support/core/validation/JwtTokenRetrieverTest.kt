package no.nav.security.token.support.core.validation

import com.nimbusds.jose.util.IOUtils
import com.nimbusds.jose.util.Resource
import com.nimbusds.jwt.JWTClaimsSet.Builder
import com.nimbusds.jwt.PlainJWT
import java.io.IOException
import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.nio.charset.StandardCharsets.*
import java.util.Date
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.http.HttpRequest.NameValue
import no.nav.security.token.support.core.validation.JwtTokenRetriever.retrieveUnvalidatedTokens

//TODO more tests, including multiple issuers setup, and multiple tokens in one header etc
@ExtendWith(MockitoExtension::class)
internal class JwtTokenRetrieverTest {

    @Mock
    private lateinit var request : HttpRequest

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeader() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
            NoopResourceRetriever())
        Mockito.`when`(request.getHeader("Authorization")).thenReturn("Bearer ${createJWT("issuer1")}")
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeader2() {
        val config = MultiIssuerConfiguration(
            createIssuerPropertiesMap("issuer1", "cookie1", "TokenXAuthorization"),
            NoopResourceRetriever())
        Mockito.`when`(request.getHeader("TokenXAuthorization")).thenReturn("Bearer ${createJWT("issuer1")}")
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeaderIssuerNotConfigured() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
            NoopResourceRetriever())
        Mockito.`when`(request.getHeader("Authorization")).thenReturn("Bearer ${createJWT("issuerNotConfigured")}")
        assertEquals(0, retrieveUnvalidatedTokens(config, request).size)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInCookie() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "cookie1"),
            NoopResourceRetriever())
        Mockito.`when`(request.getCookies()).thenReturn(arrayOf(Cookie("cookie1", createJWT("issuer1"))))
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensWhenCookieNameNotConfigured() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", null),
            NoopResourceRetriever())
        Mockito.`when`(request.getCookies()).thenReturn(arrayOf(Cookie("cookie1", "somerandomcookie")))
        Mockito.`when`(request.getHeader("Authorization")).thenReturn("Bearer ${createJWT("issuer1")}")
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensMultipleIssuersWithSameCookieName() {
        val issuerPropertiesMap = createIssuerPropertiesMap("issuer1", "cookie1")
        issuerPropertiesMap.putAll(createIssuerPropertiesMap("issuer2", "cookie1"))

        val config = MultiIssuerConfiguration(issuerPropertiesMap, NoopResourceRetriever())

        Mockito.`when`(request.getCookies()).thenReturn(arrayOf(Cookie("cookie1", createJWT("issuer1"))))
        assertEquals(1, retrieveUnvalidatedTokens(config, request).size)
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Throws(URISyntaxException::class, MalformedURLException::class)
    private fun createIssuerPropertiesMap(issuer : String, cookieName : String?) : MutableMap<String, IssuerProperties> {
        val issuerPropertiesMap : MutableMap<String, IssuerProperties> = HashMap()
        issuerPropertiesMap[issuer] = IssuerProperties(URI("https://$issuer").toURL(), listOf("aud1"), cookieName)
        return issuerPropertiesMap
    }

    @Throws(URISyntaxException::class, MalformedURLException::class)
    private fun createIssuerPropertiesMap(issuer : String, cookieName : String, headerName : String) : Map<String, IssuerProperties> {
        val issuerPropertiesMap : MutableMap<String, IssuerProperties> = HashMap()
        issuerPropertiesMap[issuer] = IssuerProperties(
            URI("https://$issuer").toURL(),
            listOf("aud1"),
            cookieName,
            headerName)
        return issuerPropertiesMap
    }

    private fun createJWT(issuer : String) : String {
        val now = Date()
        val claimsSet = Builder()
            .subject("foobar").issuer(issuer).notBeforeTime(now).issueTime(now)
            .expirationTime(Date(now.time + 3600)).build()
        return PlainJWT(claimsSet).serialize()
    }

    internal inner class NoopResourceRetriever : ProxyAwareResourceRetriever() {

        @Throws(IOException::class)
        override fun retrieveResource(url : URL) : Resource {
            var content = contentFromFile
            content = content.replace("\$ISSUER", url.toString())
            return Resource(content, "application/json")
        }

        private val contentFromFile  = IOUtils.readInputStreamToString(getInputStream("/metadata.json"), UTF_8)

        private fun getInputStream(file : String) = NoopResourceRetriever::class.java.getResourceAsStream(file)
    }

    private inner class Cookie(private val name : String, private val value : String) : NameValue {

        override fun getName()  = name

        override fun getValue() = value
    }
}
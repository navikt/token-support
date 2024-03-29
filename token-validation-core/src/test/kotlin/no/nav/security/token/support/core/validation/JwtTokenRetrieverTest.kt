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
import java.util.*
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER
import no.nav.security.token.support.core.configuration.IssuerProperties
import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.core.http.HttpRequest
import no.nav.security.token.support.core.validation.JwtTokenRetriever.retrieveUnvalidatedTokens
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever

//TODO more tests, including multiple issuers setup, and multiple tokens in one header etc
@ExtendWith(MockitoExtension::class)
internal class JwtTokenRetrieverTest {

    @Mock
    private lateinit var request : HttpRequest

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeader() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", AUTHORIZATION_HEADER),
            NoopResourceRetriever())
        whenever(request.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer ${createJWT("issuer1")}")
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeader2() {
        val config = MultiIssuerConfiguration(
            createIssuerPropertiesMap("issuer1", "TokenXAuthorization"),
            NoopResourceRetriever())
        whenever(request.getHeader("TokenXAuthorization")).thenReturn("Bearer ${createJWT("issuer1")}")
        assertEquals("issuer1", retrieveUnvalidatedTokens(config, request)[0].issuer)
    }

    @Test
    @Throws(URISyntaxException::class, MalformedURLException::class)
    fun testRetrieveTokensInHeaderIssuerNotConfigured() {
        val config = MultiIssuerConfiguration(createIssuerPropertiesMap("issuer1", "header1"),
            NoopResourceRetriever())
        whenever(request.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer ${createJWT("issuerNotConfigured")}")
        assertEquals(0, retrieveUnvalidatedTokens(config, request).size)
    }

    @Throws(URISyntaxException::class, MalformedURLException::class)
    private fun createIssuerPropertiesMap(issuer : String,  headerName : String = AUTHORIZATION_HEADER) : Map<String, IssuerProperties> {
        val issuerPropertiesMap : MutableMap<String, IssuerProperties> = HashMap()
        issuerPropertiesMap[issuer] = IssuerProperties(
            URI("https://$issuer").toURL(),
            listOf("aud1"),
            null,
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

}
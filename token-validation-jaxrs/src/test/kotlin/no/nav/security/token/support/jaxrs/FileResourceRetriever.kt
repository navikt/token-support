package no.nav.security.token.support.jaxrs

import com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON
import com.nimbusds.jose.util.IOUtils
import com.nimbusds.jose.util.Resource
import java.io.IOException
import java.net.URL
import java.nio.charset.StandardCharsets
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever

internal class FileResourceRetriever(private val metadataFile : String, private val jwksFile : String) : ProxyAwareResourceRetriever() {

    override fun retrieveResource(url : URL) =
        getContentFromFile(url)?.let { Resource(it, APPLICATION_JSON.type) } ?: super.retrieveResource(url)

    private fun getContentFromFile(url : URL) : String? {
        try {
            if (url.toString().contains("metadata")) {
                return IOUtils.readInputStreamToString(getInputStream(metadataFile), StandardCharsets.UTF_8)
            }
            if (url.toString().contains("jwks")) {
                return IOUtils.readInputStreamToString(getInputStream(jwksFile), StandardCharsets.UTF_8)
            }
            return null
        }
        catch (e : IOException) {
            throw RuntimeException(e)
        }
    }

    private fun getInputStream(file : String) = FileResourceRetriever::class.java.getResourceAsStream(file)

    override fun toString() = javaClass.simpleName + " [metadataFile=" + metadataFile + ", jwksFile=" + jwksFile + "]"
}
package no.nav.security.token.support.core.configuration

import com.nimbusds.jose.util.DefaultResourceRetriever
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Proxy.*
import java.net.Proxy.Type.*
import java.net.URISyntaxException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.ProxySelector
import java.net.URL

open class ProxyAwareResourceRetriever(proxyUrl : URL?, private val usePlainTextForHttps : Boolean,
                                       connectTimeout : Int,
                                       readTimeout : Int,
                                       sizeLimit : Int) : DefaultResourceRetriever(connectTimeout, readTimeout, sizeLimit) {

    @JvmOverloads
    constructor(proxyUrl : URL? = null, usePlainTextForHttps : Boolean = false) : this(proxyUrl, usePlainTextForHttps, DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT)

    init {
        super.setProxy(proxyFrom(proxyUrl))
    }

    private val LOG : Logger = LoggerFactory.getLogger(ProxyAwareResourceRetriever::class.java)

    @Throws(IOException::class)
    fun urlWithPlainTextForHttps(url : URL) : URL {
        try {
            if (!url.toURI().scheme.equals("https")) {
                return url
            }
            val port = if (url.port > 0) url.port else 443
            val newUrl = ("http://" + url.host + ":" + port + url.path
                + (if (url.query != null && url.query.isNotEmpty()) "?" + url.query else ""))
            LOG.debug("using plaintext connection for https url, new url is {}", newUrl)
            return URL(newUrl)
        }
        catch (e : URISyntaxException) {
            throw IOException(e)
        }
    }

    @Throws(IOException::class)
    override fun openHTTPConnection(url : URL) : HttpURLConnection {
        val urlToOpen  = if (usePlainTextForHttps) urlWithPlainTextForHttps(url) else url
        if (shouldProxy(url)) {
            LOG.trace("Connecting to {} via proxy {}", urlToOpen, proxy)
            return urlToOpen.openConnection(proxy) as HttpURLConnection
        }
        LOG.trace("Connecting to {} without proxy", urlToOpen)
        return urlToOpen.openConnection() as HttpURLConnection
    }

    fun shouldProxy(url : URL) = proxy.type() != DIRECT && !isNoProxy(url)
    private fun proxyFrom(uri : URL?) = uri?.let { Proxy(HTTP, InetSocketAddress(it.host, it.port)) } ?: NO_PROXY
    private fun isNoProxy(url: URL): Boolean {
        val noProxy = System.getenv("NO_PROXY")
        val isNoProxy = noProxy?.split(",")
            ?.any("$url"::contains) ?: false

        if (noProxy != null && isNoProxy) {
            LOG.trace("Not using proxy for $url since it is covered by the NO_PROXY setting $noProxy")
        } else {
            LOG.trace("Using proxy for $url since it is not covered by the NO_PROXY setting $noProxy")
        }

        return isNoProxy
    }

    companion object {
        const val DEFAULT_HTTP_CONNECT_TIMEOUT : Int = 21050
        const val DEFAULT_HTTP_READ_TIMEOUT : Int = 30000
        const val DEFAULT_HTTP_SIZE_LIMIT : Int = 50 * 1024

    }
}
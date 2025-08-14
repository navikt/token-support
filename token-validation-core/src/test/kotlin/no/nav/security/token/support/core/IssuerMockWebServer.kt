package no.nav.security.token.support.core

import com.nimbusds.jose.util.IOUtils
import mockwebserver3.*
import okhttp3.Headers
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import java.io.IOException
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.*
import okio.BufferedSink
import org.slf4j.LoggerFactory

class IssuerMockWebServer(val startProxyServer: Boolean = true) {

    private val log = LoggerFactory.getLogger(IssuerMockWebServer::class.java)

    private lateinit var server: MockWebServer
    private var proxyServer: MockWebServer? = null
    lateinit var discoveryUrl: URL
    var proxyUrl: URL? = null
    private set

    @Throws(IOException::class)
    fun start() {
        server = MockWebServer().apply {
            start()
            discoveryUrl = url(DISCOVERY_PATH).toUrl()
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    log.debug("received request on url={} with headers={}", request.url, request.headers)
                    log.debug("comparing path in request '{}' with '{}'", request.url.encodedPath, DISCOVERY_PATH)
                    return if (request.url.encodedPath.endsWith(DISCOVERY_PATH) == true) {
                        log.debug("returning well-known json data")
                        wellKnownJson()
                    } else {
                        log.error("path not found, returning 404")
                        MockResponse(code = 404)
                    }
                }
            }
        }

        if (startProxyServer) {
            proxyServer = MockWebServer().apply {
                dispatcher = ProxyDispatcher(discoveryUrl.toString().toHttpUrlOrNull()!!)
                start()
                proxyUrl = URI.create("http://localhost:$port").toURL()
            }
        }
    }

    @Throws(IOException::class)
    fun shutdown() {
      //  server.shutdown()
       // proxyServer?.shutdown()
    }

    fun getServer(): MockWebServer = server
    fun getProxyServer(): MockWebServer? = proxyServer
    fun isStartProxyServer(): Boolean = startProxyServer

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerMockWebServer

        if (startProxyServer != other.startProxyServer) return false
        if (server != other.server) return false
        if (proxyServer != other.proxyServer) return false
        if (discoveryUrl != other.discoveryUrl) return false
        if (proxyUrl != other.proxyUrl) return false

        return true
    }

    override fun hashCode(): Int {
        return Objects.hash(server, proxyServer, discoveryUrl, proxyUrl, startProxyServer)
    }

    override fun toString(): String {
        return "IssuerMockWebServer(server=$server, proxyServer=$proxyServer, discoveryUrl=$discoveryUrl, proxyUrl=$proxyUrl, startProxyServer=$startProxyServer)"
    }

    companion object {
        private const val DISCOVERY_PATH = "/.well-known/openid-configuration"

        private fun mockResponse(json: String): MockResponse {
            return MockResponse(200,  Headers.Companion.headersOf("Content-Type", "application/json;charset=UTF-8"),json)

        }

        private fun wellKnownJson(): MockResponse {
            return try {
                val json = IOUtils.readInputStreamToString(IssuerMockWebServer::class.java.getResourceAsStream("/metadata.json"), StandardCharsets.UTF_8)
                mockResponse(json)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }
    }

    class ProxyDispatcher(private val serverUrl: HttpUrl) : Dispatcher() {
        private val client = okhttp3.OkHttpClient.Builder().build()
        private val log = LoggerFactory.getLogger(ProxyDispatcher::class.java)


        override fun dispatch(request: RecordedRequest): MockResponse {
            val requestBuilder = Request.Builder()
                    .url(serverUrl)
                    .headers(request.headers)
                    .removeHeader("Host")

            if (request.bodySize != 0L) {
                requestBuilder.method(request.method, object : RequestBody() {
                    override fun contentType(): MediaType? {

                    return request.headers.get("Content-Type")?.toMediaTypeOrNull()
                    }

                    @Throws(IOException::class)
                    override fun writeTo(sink: BufferedSink) {
                        //request.body.clone().readAll(sink)
                    }

                    override fun contentLength(): Long {
                        return request.bodySize
                    }
                })
            }
            val req = requestBuilder.build()
            log.debug("created request to destination: {}", req)
            return try {
                client.newCall(req).execute().use { response ->
                        response.body?.let { body ->
                        MockResponse(response.code,response.headers,response.body.toString())
                } ?: MockResponse(code = 500)
                }
            } catch (e: IOException) {
                log.error("got exception when proxying request.", e)
                MockResponse(code = 500)
            }
        }
    }
}
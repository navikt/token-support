package no.nav.security.token.support.client.spring.oauth2


import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.springframework.http.HttpHeaders.CONTENT_TYPE
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE
import java.io.IOException
import java.util.function.Consumer

internal object TestUtils {
    @Throws(IOException::class)
    fun withMockServer(port: Int, test: Consumer<MockWebServer?>) {
        val server = MockWebServer()
        server.start(port)
        test.accept(server)
        server.shutdown()
    }

    @Throws(IOException::class)
    fun withMockServer(test: Consumer<MockWebServer?>) {
        withMockServer(0, test)
    }

    fun jsonResponse(json: String?): MockResponse {
        return MockResponse()
            .setHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
            .setBody(json!!)
    }
}
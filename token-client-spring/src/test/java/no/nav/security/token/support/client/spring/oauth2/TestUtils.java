package no.nav.security.token.support.client.spring.oauth2;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.function.Consumer;

class TestUtils {

    static void withMockServer(int port, Consumer<MockWebServer> test) throws IOException{
        MockWebServer server = new MockWebServer();
        server.start(port);
        test.accept(server);
        server.shutdown();
    }

    static void withMockServer(Consumer<MockWebServer> test) throws IOException {
        withMockServer(0, test);
    }

    static MockResponse jsonResponse(String json) {
        return new MockResponse()
            .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .setBody(json);
    }
}

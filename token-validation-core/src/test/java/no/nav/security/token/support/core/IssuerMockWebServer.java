package no.nav.security.token.support.core;

import com.nimbusds.jose.util.IOUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.BufferedSink;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Data
public class IssuerMockWebServer {
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private MockWebServer server;
    private MockWebServer proxyServer;
    private URL discoveryUrl;
    private URL proxyUrl;

    public void start() throws IOException {
        this.server = new MockWebServer();
        this.server.start();
        this.discoveryUrl = this.server.url(DISCOVERY_PATH).url();
        this.server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                log.info("received request on url={} with headers={}", request.getRequestUrl(), request.getHeaders());
                log.debug("path():{} compared to {}", request.getRequestUrl().encodedPath(), DISCOVERY_PATH);
                if (request.getRequestUrl().encodedPath().endsWith(DISCOVERY_PATH)) {
                    return wellKnownJson();
                } else {
                    return new MockResponse().setResponseCode(404);
                }
            }
        });

        this.proxyServer = new MockWebServer();
        this.proxyServer.setDispatcher(new ProxyDispatcher(HttpUrl.parse(discoveryUrl.toString())));
        this.proxyServer.start();
        this.proxyUrl = URI.create("http://localhost:" + this.proxyServer.getPort()).toURL();
    }

    public void shutdown() throws IOException {
        server.shutdown();
        proxyServer.shutdown();
    }

    private static MockResponse mockResponse(String json) {
        return new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json;charset=UTF-8")
            .setBody(json);
    }

    private static MockResponse wellKnownJson() {
        try {
            String json = IOUtils.readInputStreamToString(
                IssuerMockWebServer.class.getResourceAsStream("/metadata.json"), StandardCharsets.UTF_8);
            return mockResponse(json);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static class ProxyDispatcher extends Dispatcher {
        private final OkHttpClient client;
        private final HttpUrl serverUrl;

        ProxyDispatcher(HttpUrl url) {
            serverUrl = url;
            client = new OkHttpClient.Builder().build();
        }

        @Override
        public MockResponse dispatch(final RecordedRequest recordedRequest) {
            Request.Builder requestBuilder = new Request.Builder()
                .url(serverUrl)
                .headers(recordedRequest.getHeaders())
                .removeHeader("Host");

            if (recordedRequest.getBodySize() != 0) {
                requestBuilder.method(recordedRequest.getMethod(), new RequestBody() {
                    @Override
                    public MediaType contentType() {
                        return MediaType.parse(recordedRequest.getHeader("Content-Type"));
                    }

                    @Override
                    public void writeTo(BufferedSink sink) throws IOException {
                        recordedRequest.getBody().clone().readAll(sink);
                    }

                    @Override
                    public long contentLength() {
                        return recordedRequest.getBodySize();
                    }
                });
            }
            Request request = requestBuilder.build();
            log.info("created request to destination: {}", request);
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                if (body != null) {
                    return new MockResponse()
                        .setHeaders(response.headers())
                        .setBody(body.string())
                        .setResponseCode(response.code());
                } else {
                    return new MockResponse()
                        .setStatus("proxy error, response body from destination was null")
                        .setResponseCode(500);
                }
            } catch (IOException e) {
                log.error("got exception when proxying request.", e);
                return new MockResponse()
                    .setStatus("proxy error: " + e.getMessage())
                    .setResponseCode(500);
            }
        }
    }
}
